"""Page 7: Simulation. Start a synthetic data run on the generator and watch its progress (spec 11.1).

This is the one page that talks to the generator control API directly (HC_GENERATOR_URL).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Optional

import streamlit as st

PROFILES = ["eval", "benign_train"]
SCENARIOS = ["apt_chain", "phishing", "lateral_movement", "credential_dumping", "c2"]
DEFAULT_SEED = {"eval": 2002, "benign_train": 1001}
POLL_SECONDS = 1.0
POLL_LIMIT_SECONDS = 600


def generator_url() -> str:
    return os.getenv("HC_GENERATOR_URL", "http://generator:8300").rstrip("/")


def request(method: str, path: str, body: Optional[dict] = None, base: Optional[str] = None) -> dict[str, Any]:
    """Call the generator. Raises RuntimeError with a readable message (never the key or a traceback)."""
    headers = {"X-API-Key": os.getenv("HC_API_KEY", ""), "Content-Type": "application/json"}
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request((base or generator_url()) + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("error", {}).get("message")
        except (ValueError, AttributeError):
            detail = None
        if exc.code == 401:
            detail = "The generator rejected the API key (check HC_API_KEY)."
        raise RuntimeError(detail or f"Generator returned HTTP {exc.code}.") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise RuntimeError("Cannot reach the generator service. Is it running?") from None


def build_payload(profile: str, scenarios: list[str], seed: int, duration_hours: float, speed: str,
                  events_per_host_hour: Optional[float] = None) -> dict[str, Any]:
    """Body for POST /v1/run. benign_train never carries scenarios."""
    payload: dict[str, Any] = {"profile": profile, "scenarios": [] if profile == "benign_train" else scenarios,
                               "seed": int(seed), "duration_hours": float(duration_hours), "speed": speed}
    if events_per_host_hour:
        payload["events_per_host_hour"] = float(events_per_host_hour)
    return payload


def progress_fraction(status: dict[str, Any]) -> float:
    total = int(status.get("total") or 0)
    if status.get("state") == "done" and not status.get("error"):
        return 1.0
    return min(1.0, int(status.get("produced") or 0) / total) if total else 0.0


def describe(status: dict[str, Any]) -> str:
    state = status.get("state", "idle")
    if state == "idle":
        return "No run yet."
    if status.get("error"):
        return f"Run {status.get('run_id', '')[:8]} failed: {status['error']}"
    return f"Run {status.get('run_id', '')[:8]} is {state}: {status.get('produced', 0)} of {status.get('total', 0)} events."


def show_status(status: dict[str, Any]) -> None:
    st.progress(progress_fraction(status))
    if status.get("error"):
        st.error(describe(status))
        return
    st.write(describe(status))
    cols = st.columns(3)
    cols[0].metric("Produced", status.get("produced", 0))
    cols[1].metric("Total", status.get("total", 0))
    cols[2].metric("State", status.get("state", "idle"))
    if status.get("labels_path"):
        st.caption(f"Labels written to {status['labels_path']}")


def watch(placeholder: Any) -> None:
    """Poll until the run is done (or the page limit is reached)."""
    started = time.monotonic()
    while time.monotonic() - started < POLL_LIMIT_SECONDS:
        status = request("GET", "/v1/status")
        with placeholder.container():
            show_status(status)
        if status.get("state") != "running":
            return
        time.sleep(POLL_SECONDS)


def main() -> None:
    try:
        st.set_page_config(page_title="Simulation", layout="wide")
    except Exception:  # noqa: BLE001 - already configured by the shell
        pass
    st.title("Simulation")
    st.caption("Generate synthetic telemetry into the pipeline. All data is synthetic.")
    left, right = st.columns(2)
    with left:
        profile = st.selectbox("Profile", PROFILES, help="benign_train has no attacks. eval adds attack scenarios.")
        picked = st.multiselect("Scenarios", SCENARIOS, default=["apt_chain"], disabled=profile == "benign_train")
        speed = st.radio("Speed", ["burst", "realtime"], horizontal=True)
    with right:
        seed = st.number_input("Seed", min_value=0, max_value=2**31 - 1, value=DEFAULT_SEED[profile], step=1)
        hours = st.number_input("Duration (hours)", min_value=1, max_value=168, value=24, step=1)
        rate = st.number_input("Events per workstation-hour at peak (0 = default)", min_value=0, max_value=5000,
                               value=0, step=10)
    placeholder = st.empty()
    start, refresh = st.columns(2)
    try:
        if start.button("Start run", type="primary"):
            if profile == "eval" and not picked:
                st.warning("Pick at least one scenario, or choose benign_train.")
            else:
                run = request("POST", "/v1/run", build_payload(profile, picked, int(seed), float(hours), speed,
                                                              float(rate) or None))
                st.success(f"Run started: {run.get('run_id', '')[:8]}")
                watch(placeholder)
        elif refresh.button("Refresh status"):
            with placeholder.container():
                show_status(request("GET", "/v1/status"))
    except RuntimeError as exc:
        st.error(str(exc))


if __name__ == "__main__":
    main()
