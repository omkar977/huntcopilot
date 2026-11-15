"""End-to-end test (spec Section 14). Owner: Lead. Standard library only.

Run after `docker compose up -d --build` (all services healthy):
    HC_API_KEY=<same key as in .env> python tests/e2e/run_e2e.py
Windows PowerShell:  $env:HC_API_KEY='<key>'; python tests\\e2e\\run_e2e.py
Options: --skip-generate (data already loaded), --intent "text".
Exit code 0 only if every check passes. Prints PASS/FAIL per step; never prints the key.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request

API = os.getenv("HC_API_URL_LOCAL", "http://127.0.0.1:8000")
ML = os.getenv("HC_ML_URL_LOCAL", "http://127.0.0.1:8100")
DET = os.getenv("HC_DETECTOR_URL_LOCAL", "http://127.0.0.1:8200")
GEN = os.getenv("HC_GENERATOR_URL_LOCAL", "http://127.0.0.1:8300")
ING = os.getenv("HC_INGESTOR_URL_LOCAL", "http://127.0.0.1:8301")


def _key_from_env_file() -> str:
    """Read HC_API_KEY from deploy/compose/.env (same file the containers use). Trims spaces and quotes."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "deploy", "compose", ".env")
    try:
        with open(path, encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("HC_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return ""


KEY = _key_from_env_file() or os.getenv("HC_API_KEY", "").strip()
DEMO = "Find lateral movement after suspicious PowerShell"
EVAL_DAY = {"start": "2026-11-12T00:00:00Z", "end": "2026-11-13T00:00:00Z"}
results: list = []


def call(method, url, body=None, timeout=120, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"X-API-Key": KEY, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode()
            return text if raw else (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        raise RuntimeError(f"HTTP {exc.code} from {url.split('/', 3)[-1]}: {detail}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"cannot reach {url.split('/', 3)[2]} ({exc})") from None


def check(name, fn):
    try:
        info = fn()
        results.append((name, True))
        shown = info if isinstance(info, str) else (json.dumps(info) if info and len(json.dumps(info)) < 160 else "")
        print(f"PASS  {name}" + (f"  {shown}" if shown else ""))
        return info
    except Exception as exc:  # noqa: BLE001 - report and continue
        results.append((name, False))
        print(f"FAIL  {name}  {exc}")
        return None


def wait_generator(label, timeout=900):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = call("GET", GEN + "/v1/status")
        if st.get("state") == "done":
            if st.get("error"):
                raise RuntimeError("generator error: " + st["error"])
            return st
        time.sleep(3)
    raise RuntimeError(f"generator did not finish ({label}) in {timeout}s")


def wait_events(minimum, timeout=600):
    t0 = time.time()
    n = 0
    while time.time() - t0 < timeout:
        n = (call("GET", API + "/v1/stats").get("events")) or 0
        if n >= minimum:
            return n
        time.sleep(5)
    raise RuntimeError(f"only {n} events in OpenSearch after {timeout}s (wanted {minimum})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-generate", action="store_true")
    ap.add_argument("--intent", default=DEMO)
    args = ap.parse_args()
    if not KEY:
        print("HC_API_KEY not found: set it in deploy/compose/.env")
        return 2

    def health():
        out = {}
        for name, url in (("api", API), ("ml", ML), ("detector", DET), ("generator", GEN), ("ingestor", ING)):
            out[name] = call("GET", url + "/health", timeout=10).get("status", "?")
        bad = {k: v for k, v in out.items() if v not in ("ok", "healthy", "running", "ready")}
        if bad:
            raise RuntimeError(f"not healthy: {bad}")
        return out
    if check("1 all services healthy", health) is None:
        return 1

    if not args.skip_generate:
        def gen_train():
            call("POST", GEN + "/v1/run", {"profile": "benign_train", "seed": 1001})
            st = wait_generator("train")
            n = wait_events(int(st.get("produced", 0)) * 0.98)
            return f"produced {st.get('produced')} events, in OpenSearch {n}"
        check("2 generate training data (seed 1001)", gen_train)
    check("3 train the ML model", lambda: {k: v for k, v in call("POST", ML + "/v1/train", {"seed": 1001}).items()
                                            if k in ("model_id", "trained_at")})
    if not args.skip_generate:
        def gen_eval():
            before = (call("GET", API + "/v1/stats").get("events")) or 0
            call("POST", GEN + "/v1/run", {"profile": "eval", "scenarios": ["apt_chain"], "seed": 2002})
            st = wait_generator("eval")
            n = wait_events(before + int(st.get("produced", 0)) * 0.98)
            return f"produced {st.get('produced')} events, total in OpenSearch {n}"
        check("4 generate evaluation data (seed 2002)", gen_eval)

    def detect():
        out = call("POST", DET + "/v1/run-batch", EVAL_DAY)
        per = out.get("per_rule", {})
        missing = [f"HC-00{i}" for i in range(1, 10) if f"HC-00{i}" not in per]
        if missing:
            raise RuntimeError(f"rules without alerts: {missing}")
        return f"alerts_total {out.get('alerts_total')}, rules fired {len(per)}"
    check("5 run detector batch", detect)

    plan = check("6 create hunt plan", lambda: call("POST", API + "/v1/hunts", {"intent": args.intent}))
    run = None
    if plan:
        print(f"      plan source={plan.get('source')} template={plan.get('template')} valid={plan['validation']['ok']}")
        run = check("7 run hunt", lambda: call("POST", API + f"/v1/hunts/{plan['plan_id']}/run", timeout=180))
    finding = None
    if run:
        def findings():
            items = sorted(run.get("findings") or [], key=lambda f: -f["scores"]["confidence"])
            if not items:
                raise RuntimeError(f"no findings (run status {run.get('status')}, {run.get('error', '')})")
            top = items[0]
            hh = sum(1 for e in top["chain"]["edges"] if e["src"].startswith("host:") and e["dst"].startswith("host:"))
            props = call("GET", API + "/v1/proposals?status=pending").get("total", 0)
            problems = []
            if top["scores"]["confidence"] < 60:
                problems.append(f"confidence {top['scores']['confidence']} < 60")
            if hh < 2:
                problems.append(f"host-to-host edges {hh} < 2")
            if props < 1:
                problems.append("no pending proposals")
            if problems:
                raise RuntimeError("; ".join(problems))
            return f"{len(items)} finding(s); top conf {top['scores']['confidence']:.0f}, hosts {top['hosts']}, host-to-host edges {hh}, pending proposals {props}"
        if check("8 finding, chain, proposals", findings):
            finding = sorted(run["findings"], key=lambda f: -f["scores"]["confidence"])[0]

    def approve():
        pend = call("GET", API + "/v1/proposals?status=pending").get("items") or []
        if not pend:
            raise RuntimeError("nothing to approve")
        out = call("POST", API + f"/v1/proposals/{pend[0]['proposal_id']}/approve",
                   {"approver": "e2e-analyst", "confirm": True})
        if out.get("status") not in ("executed",):
            raise RuntimeError(f"proposal status {out.get('status')}")
        ver = call("GET", API + "/v1/audit/verify")
        if not ver.get("ok"):
            raise RuntimeError(f"audit chain broken at {ver.get('first_bad_seq')}")
        return f"{pend[0]['action']} {pend[0]['target']} executed; audit chain ok"
    check("9 approve one proposal, verify audit", approve)

    if finding:
        def export():
            fid = finding["finding_id"]
            js = call("GET", API + f"/v1/cases/{fid}/export?format=json", raw=True)
            md = call("GET", API + f"/v1/cases/{fid}/export?format=md", raw=True)
            rationale = finding["rationale"][:40]
            for label, text in (("json", js), ("md", md)):
                if fid not in text or rationale not in text:
                    raise RuntimeError(f"{label} export misses the finding id or the rationale")
            return f"json {len(js)} bytes, md {len(md)} bytes"
        check("10 export case json and md", export)

    def evaluate():
        out = call("POST", ML + "/v1/evaluate", {"time_range": EVAL_DAY}, timeout=300)
        keep = {k: out.get(k) for k in ("precision", "recall", "f1", "pr_auc", "false_positives_per_host_day")}
        return json.dumps(keep)
    check("11 ML evaluation (record for the report)", evaluate)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed" + (f"; FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())