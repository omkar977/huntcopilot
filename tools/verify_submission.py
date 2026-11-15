#!/usr/bin/env python3
"""Check a member zip before it is sent to the Lead (standard library only). Owner: Lead.

Usage:  python tools/verify_submission.py HC_M2_detect_v1_20261112-2050.zip [--no-tests] [--keep]
Checks, in order: name and member code, zip safety, allowed paths, forbidden files, MANIFEST headings,
test and lint evidence files, secret scan, compile check, ruff (if installed), pytest (must pass),
ground-truth guard. Prints a table and a final PASS or FAIL. Exit code 0 on PASS, 1 on FAIL.

Ground-truth guard scope: quoted key 'gt', attribute .gt and gt.is_malicious style names are rejected in
libs/hc_ml (except evaluate.py and tests) and in services/api/agent. In libs/hc_hunt only names such as
gt.is_malicious or 'gt.scenario' are rejected, because the executor must mention gt to EXCLUDE it.
"""
from __future__ import annotations

import argparse
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SKELETON = Path(__file__).resolve().parent.parent

ALLOWED = {
    "M1": ["services/generator/", "services/ingestor/", "deploy/", "services/dashboard/pages/7_"],
    "M2": ["libs/hc_detect/", "libs/hc_hunt/", "services/detector/",
           "services/dashboard/pages/1_", "services/dashboard/pages/3_"],
    "M3": ["libs/hc_ml/", "services/ml/", "services/dashboard/pages/6_"],
    "M4": ["services/api/", "services/dashboard/pages/2_", "services/dashboard/pages/4_",
           "services/dashboard/pages/5_"],
}
ROOT_FILES = {"MANIFEST.md", "CHANGE_REQUEST.md", "pytest_output.txt", "ruff_output.txt"}
FORBIDDEN_DIRS = {".venv", "venv", "__pycache__", ".git", ".pytest_cache", ".ruff_cache", "node_modules", "mlruns"}
FORBIDDEN_FILES = ["*.pyc", ".env", "*.env", "*.pem", "*.key"]
MAX_BYTES = 5 * 1024 * 1024
MANIFEST_HEADINGS = ["Implemented", "How to run the tests", "Test summary", "Assumptions made",
                     "Known issues", "Contract change requests", "New dependencies"]
NAME_RE = re.compile(r"^HC_(M[1-4])_[A-Za-z0-9\-]+_v(\d+)_(\d{8}-\d{4})\.zip$")

SECRET_PATTERNS = [
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Groq-style key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}")),
    ("sk- style key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("literal secret", re.compile(r"(?i)\b(password|passwd|api_key|apikey|secret|token)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
]
SAFE_WORDS = ("example", "placeholder", "changeme", "dummy", "test", "xxxx", "your_", "<", "env", "fake")

GT_FULL = re.compile(r"""['"]gt['"]|['"]gt\.|\.gt\b|\bgt\.(?:is_malicious|scenario|stage)""")
GT_HUNT = re.compile(r"""['"]gt\.|\bgt\.(?:is_malicious|scenario|stage)""")


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.rows.append((name, status, detail))

    @property
    def failed(self) -> bool:
        return any(s == "FAIL" for _, s, _ in self.rows)

    def print(self) -> None:
        width = max(len(n) for n, _, _ in self.rows) if self.rows else 10
        for name, status, detail in self.rows:
            print(f"{status:5} {name:<{width}}  {detail}")
        print("\nFINAL RESULT:", "FAIL" if self.failed else "PASS")


def is_text(path: Path) -> bool:
    try:
        return path.stat().st_size <= 1_000_000 and b"\0" not in path.read_bytes()[:2048]
    except OSError:
        return False


def check_zip_safety(zf: zipfile.ZipFile, rep: Report) -> bool:
    bad = [n for n in zf.namelist() if n.startswith("/") or ".." in Path(n).parts or "\\" in n]
    if bad:
        rep.add("zip safety", "FAIL", f"unsafe paths: {bad[:3]}")
        return False
    rep.add("zip safety", "PASS")
    return True


def check_paths(files: list[str], member: str, rep: Report) -> None:
    allowed = ALLOWED[member]
    bad = []
    for f in files:
        if "/" not in f:
            if f not in ROOT_FILES:
                bad.append(f)
        elif not any(f.startswith(p) for p in allowed):
            bad.append(f)
    rep.add("allowed paths", "FAIL" if bad else "PASS", f"outside {member} paths: {bad[:5]}" if bad else "")


def check_forbidden(root: Path, rep: Report) -> None:
    bad = []
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        if any(part in FORBIDDEN_DIRS for part in rel.parts):
            bad.append(str(rel))
        elif p.is_file():
            if any(fnmatch.fnmatch(p.name, pat) for pat in FORBIDDEN_FILES) or p.stat().st_size > MAX_BYTES:
                bad.append(str(rel))
    rep.add("forbidden files", "FAIL" if bad else "PASS", f"{bad[:5]}" if bad else "")


def check_manifest(root: Path, rep: Report) -> None:
    mf = root / "MANIFEST.md"
    if not mf.exists():
        rep.add("MANIFEST.md", "FAIL", "missing")
        return
    text = mf.read_text(encoding="utf-8", errors="ignore").lower()
    missing = [h for h in MANIFEST_HEADINGS if h.lower() not in text]
    rep.add("MANIFEST.md", "FAIL" if missing else "PASS", f"missing headings: {missing}" if missing else "")


def check_evidence(root: Path, rep: Report) -> None:
    po = root / "pytest_output.txt"
    if not po.exists():
        rep.add("pytest_output.txt", "FAIL", "missing")
    else:
        t = po.read_text(encoding="utf-8", errors="ignore").lower()
        ok = "passed" in t and " failed" not in t and " error" not in t
        rep.add("pytest_output.txt", "PASS" if ok else "FAIL", "" if ok else "must show passed and no failures")
    rep.add("ruff_output.txt", "PASS" if (root / "ruff_output.txt").exists() else "FAIL",
            "" if (root / "ruff_output.txt").exists() else "missing")


def check_secrets(root: Path, rep: Report) -> None:
    hits = []
    for p in root.rglob("*"):
        if not p.is_file() or not is_text(p):
            continue
        for lineno, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            for name, rx in SECRET_PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                if name == "literal secret" and any(w in m.group(2).lower() or w in line.lower() for w in SAFE_WORDS):
                    continue
                hits.append(f"{p.relative_to(root)}:{lineno} {name}")
    rep.add("secret scan", "FAIL" if hits else "PASS", f"{hits[:5]}" if hits else "")


def run(cmd: list[str], cwd: Path, env: dict | None = None) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr)[-4000:]


def check_compile(root: Path, rep: Report) -> None:
    code, out = run([sys.executable, "-m", "compileall", "-q", "."], root)
    rep.add("compile check", "PASS" if code == 0 else "FAIL", "" if code == 0 else out.strip()[-300:])


def check_ruff(root: Path, rep: Report) -> None:
    ruff = shutil.which("ruff")
    if not ruff:
        rep.add("ruff", "SKIP", "ruff not installed (pip install ruff)")
        return
    cfg = SKELETON / "ruff.toml"
    code, out = run([ruff, "check", "--config", str(cfg), "."], root)
    rep.add("ruff", "PASS" if code == 0 else "FAIL", "" if code == 0 else out.strip()[-300:])


def check_pytest(root: Path, rep: Report) -> None:
    code, _ = run([sys.executable, "-m", "pytest", "--version"], root)
    if code != 0:
        rep.add("pytest", "FAIL", "pytest not installed (pip install -r requirements-dev.txt)")
        return
    if not (root / "conftest.py").exists():
        shutil.copy(SKELETON / "conftest.py", root / "conftest.py")
    fixtures_dst = root / "tests" / "fixtures"
    if not fixtures_dst.exists():
        shutil.copytree(SKELETON / "tests" / "fixtures", fixtures_dst)
    paths = [str(SKELETON / "common"), str(root / "libs")]
    paths += [str(p) for p in (root / "services").glob("*") if p.is_dir()] if (root / "services").exists() else []
    paths += [str(p) for p in (root / "libs").glob("*") if p.is_dir()] if (root / "libs").exists() else []
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(paths), HC_FIXTURES=str(fixtures_dst))
    code, out = run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"], root, env)
    rep.add("pytest", "PASS" if code == 0 else "FAIL", "" if code == 0 else out.strip()[-400:])


def check_gt_guard(root: Path, rep: Report) -> None:
    hits = []

    def scan(base: str, rx: re.Pattern, skip_names: tuple[str, ...] = ()) -> None:
        d = root / base
        if not d.exists():
            return
        for p in d.rglob("*.py"):
            rel = p.relative_to(root)
            if "tests" in rel.parts or p.name in skip_names or p.name.startswith("test_"):
                continue
            for lineno, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if line.strip().startswith("#"):
                    continue
                if rx.search(line):
                    hits.append(f"{rel}:{lineno}")

    scan("libs/hc_ml", GT_FULL, skip_names=("evaluate.py",))
    scan("services/api/agent", GT_FULL)
    scan("libs/hc_hunt", GT_HUNT)
    rep.add("ground-truth guard", "FAIL" if hits else "PASS", f"{hits[:5]}" if hits else "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("zipfile")
    ap.add_argument("--no-tests", action="store_true", help="skip compile, ruff and pytest")
    ap.add_argument("--keep", action="store_true", help="keep the temporary folder")
    args = ap.parse_args()
    rep = Report()
    zpath = Path(args.zipfile)
    m = NAME_RE.match(zpath.name)
    if not m:
        rep.add("file name", "FAIL", "expected HC_<M1..M4>_<module>_v<N>_<YYYYMMDD-HHMM>.zip")
        rep.print()
        return 1
    member = m.group(1)
    rep.add("file name", "PASS", f"member {member}, version {m.group(2)}")
    if not zpath.exists():
        rep.add("file exists", "FAIL", str(zpath))
        rep.print()
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="hc_verify_"))
    try:
        with zipfile.ZipFile(zpath) as zf:
            if not check_zip_safety(zf, rep):
                rep.print()
                return 1
            zf.extractall(tmp)
            files = [n for n in zf.namelist() if not n.endswith("/") and Path(n).name != ".gitkeep"]
        check_paths(files, member, rep)
        check_forbidden(tmp, rep)
        check_manifest(tmp, rep)
        check_evidence(tmp, rep)
        check_secrets(tmp, rep)
        if not args.no_tests:
            check_compile(tmp, rep)
            check_ruff(tmp, rep)
            check_pytest(tmp, rep)
        check_gt_guard(tmp, rep)
        rep.print()
        return 1 if rep.failed else 0
    finally:
        if args.keep:
            print("kept:", tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
