"""SQLite persistence (plans, runs, findings, proposals, simulated state tables).

Uses the standard-library sqlite3 module (assumption A1 in MANIFEST.md): the data model is small and
this keeps the service free of an ORM dependency. The database file is HC_DB_URL (sqlite:///path).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any, Optional

from hc_common.schemas import Finding, HuntPlan, HuntRun, Proposal

SCHEMA = """
CREATE TABLE IF NOT EXISTS plans (plan_id TEXT PRIMARY KEY, created_at TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, plan_id TEXT, status TEXT, started_at TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (finding_id TEXT PRIMARY KEY, run_id TEXT, confidence REAL, hosts TEXT,
    created_at TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS proposals (proposal_id TEXT PRIMARY KEY, finding_id TEXT, action TEXT, target TEXT,
    status TEXT, requested_at TEXT, doc TEXT NOT NULL, UNIQUE(finding_id, action, target));
CREATE TABLE IF NOT EXISTS host_state (host TEXT PRIMARY KEY, isolated INTEGER NOT NULL, updated_at TEXT);
CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, blocked_at TEXT);
CREATE TABLE IF NOT EXISTS disabled_accounts (user TEXT PRIMARY KEY, disabled_at TEXT);
CREATE TABLE IF NOT EXISTS killed_processes (id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, process TEXT,
    killed_at TEXT);
"""


def sqlite_path(db_url: str) -> str:
    """Convert sqlite:////data/hc.db to /data/hc.db (and sqlite:///x.db to x.db)."""
    url = db_url.strip()
    if not url.startswith("sqlite:"):
        raise ValueError("HC_DB_URL must start with sqlite:")
    path = url[len("sqlite:"):]
    if path.startswith("///"):
        path = path[3:]
    elif path.startswith("//"):
        path = path[2:]
    return path or ":memory:"


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


class _Result:
    """Rows already fetched from a statement."""

    def __init__(self, rows: list, rowcount: int) -> None:
        self._rows, self.rowcount = rows, rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list:
        return self._rows


class Store:
    """Thread-safe wrapper around one sqlite3 connection."""

    def __init__(self, db_url: str) -> None:
        path = sqlite_path(db_url)
        if path != ":memory:":
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _exec(self, sql: str, args: tuple = ()) -> "_Result":
        """Execute and fetch under the lock so concurrent threads cannot interleave on the connection."""
        with self._lock:
            cur = self._conn.execute(sql, args)
            return _Result(cur.fetchall(), cur.rowcount)

    def _all(self, sql: str, args: tuple = ()) -> list:
        return self._exec(sql, args).fetchall()

    # ------------------------------------------------------------ plans and runs
    def put_plan(self, plan: HuntPlan) -> None:
        self._exec("INSERT OR REPLACE INTO plans VALUES (?,?,?)",
                   (plan.plan_id, _iso(plan.created_at), plan.model_dump_json()))

    def get_plan(self, plan_id: str) -> Optional[HuntPlan]:
        row = self._exec("SELECT doc FROM plans WHERE plan_id=?", (plan_id,)).fetchone()
        return HuntPlan.model_validate_json(row["doc"]) if row else None

    def put_run(self, run: HuntRun) -> None:
        self._exec("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?)",
                   (run.run_id, run.plan_id, run.status, _iso(run.started_at), run.model_dump_json()))

    def get_run(self, run_id: str) -> Optional[HuntRun]:
        row = self._exec("SELECT doc FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return HuntRun.model_validate_json(row["doc"]) if row else None

    # ------------------------------------------------------------ findings
    def put_finding(self, f: Finding) -> None:
        self._exec("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?)",
                   (f.finding_id, f.run_id, f.scores.confidence, json.dumps(sorted(f.hosts)),
                    _iso(f.created_at), f.model_dump_json()))

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        row = self._exec("SELECT doc FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        return Finding.model_validate_json(row["doc"]) if row else None

    def list_findings(self, min_confidence: float = 0.0, host: str = "", limit: int = 100) -> tuple[list[Finding], int]:
        where, args = ["confidence >= ?"], [min_confidence]
        if host:
            where.append("EXISTS (SELECT 1 FROM json_each(findings.hosts) WHERE value = ?)")
            args.append(host)
        clause = " AND ".join(where)
        total = self._exec(f"SELECT COUNT(*) AS n FROM findings WHERE {clause}", tuple(args)).fetchone()["n"]
        rows = self._all(
            f"SELECT doc FROM findings WHERE {clause} ORDER BY confidence DESC, finding_id ASC LIMIT ?",
            tuple(args) + (limit,),
        )
        return [Finding.model_validate_json(r["doc"]) for r in rows], total

    def count(self, table: str) -> int:
        if table not in {"plans", "runs", "findings", "proposals"}:
            raise ValueError(table)
        return self._exec(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]

    # ------------------------------------------------------------ proposals
    def insert_proposal(self, p: Proposal) -> bool:
        """Insert a proposal. Returns False if (finding_id, action, target) already exists."""
        try:
            self._exec("INSERT INTO proposals VALUES (?,?,?,?,?,?,?)",
                       (p.proposal_id, p.finding_id, p.action, p.target, p.status,
                        _iso(p.requested_at), p.model_dump_json()))
            return True
        except sqlite3.IntegrityError:
            return False

    def find_proposal(self, finding_id: str, action: str, target: str) -> Optional[Proposal]:
        row = self._exec("SELECT doc FROM proposals WHERE finding_id=? AND action=? AND target=?",
                         (finding_id, action, target)).fetchone()
        return Proposal.model_validate_json(row["doc"]) if row else None

    def get_proposal(self, proposal_id: str) -> Optional[Proposal]:
        row = self._exec("SELECT doc FROM proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
        return Proposal.model_validate_json(row["doc"]) if row else None

    def update_proposal_if(self, p: Proposal, expected_status: str) -> bool:
        """Atomic compare-and-set on status. Returns False if the stored status is not expected_status."""
        cur = self._exec("UPDATE proposals SET status=?, doc=? WHERE proposal_id=? AND status=?",
                         (p.status, p.model_dump_json(), p.proposal_id, expected_status))
        return cur.rowcount == 1

    def list_proposals(self, status: str = "", finding_id: str = "", limit: int = 100) -> tuple[list[Proposal], int]:
        where, args = ["1=1"], []
        if status:
            where.append("status = ?")
            args.append(status)
        if finding_id:
            where.append("finding_id = ?")
            args.append(finding_id)
        clause = " AND ".join(where)
        total = self._exec(f"SELECT COUNT(*) AS n FROM proposals WHERE {clause}", tuple(args)).fetchone()["n"]
        rows = self._all(f"SELECT doc FROM proposals WHERE {clause} ORDER BY requested_at DESC, proposal_id LIMIT ?",
                         tuple(args) + (limit,))
        return [Proposal.model_validate_json(r["doc"]) for r in rows], total

    def proposal_counts(self) -> dict[str, int]:
        rows = self._all("SELECT status, COUNT(*) AS n FROM proposals GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    # ------------------------------------------------------------ simulated state tables
    def sim_isolate(self, host: str, when: str) -> None:
        self._exec("INSERT OR REPLACE INTO host_state VALUES (?,?,?)", (host, 1, when))

    def sim_block_ip(self, ip: str, when: str) -> None:
        self._exec("INSERT OR REPLACE INTO blocked_ips VALUES (?,?)", (ip, when))

    def sim_disable_account(self, user: str, when: str) -> None:
        self._exec("INSERT OR REPLACE INTO disabled_accounts VALUES (?,?)", (user, when))

    def sim_kill_process(self, host: str, process: str, when: str) -> None:
        self._exec("INSERT INTO killed_processes (host, process, killed_at) VALUES (?,?,?)", (host, process, when))

    def state_snapshot(self) -> dict[str, Any]:
        def rows(sql: str) -> list[dict]:
            return [dict(r) for r in self._all(sql)]

        return {
            "host_state": [dict(r, isolated=bool(r["isolated"])) for r in
                           self._all("SELECT host, isolated, updated_at FROM host_state ORDER BY host")],
            "blocked_ips": rows("SELECT ip, blocked_at FROM blocked_ips ORDER BY ip"),
            "disabled_accounts": rows("SELECT user, disabled_at FROM disabled_accounts ORDER BY user"),
            "killed_processes": rows("SELECT id, host, process, killed_at FROM killed_processes ORDER BY id"),
        }
