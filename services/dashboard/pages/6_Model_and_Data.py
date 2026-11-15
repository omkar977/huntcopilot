"""Page 6: model metadata, evaluation and feature z-scores (owner M3).

The ml service endpoints are not part of the api, so this page uses a small self-contained client
(same pattern as api_client.py). The Lead may move these helpers into api_client.py.
"""
import os

import httpx
import pandas as pd
import streamlit as st

ML_URL = os.getenv("HC_ML_URL", "http://ml:8100").rstrip("/")
MLFLOW_UI = os.getenv("HC_MLFLOW_UI_URL", "http://localhost:5000")
DEFAULT_START = "2026-11-12T00:00:00Z"
DEFAULT_END = "2026-11-13T00:00:00Z"


def _call(method: str, path: str, payload: dict | None = None, timeout: float = 30.0) -> dict:
    """Call the ml service and return JSON; raise RuntimeError with a readable message on any failure."""
    try:
        resp = httpx.request(method, ML_URL + path, json=payload, timeout=timeout)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"ml service not reachable ({type(exc).__name__})") from exc
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if resp.status_code >= 400:
        err = body.get("error", {}) if isinstance(body, dict) else {}
        raise RuntimeError(f"{err.get('code', resp.status_code)}: {err.get('message', 'request failed')}")
    return body


def _show_meta() -> None:
    st.subheader("Current model")
    try:
        meta = _call("GET", "/v1/models/current")
    except RuntimeError as exc:
        st.warning(f"No model information: {exc}")
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("Model id", meta["model_id"][:12])
    c2.metric("Trained at", meta["trained_at"])
    c3.metric("Training events", meta["train_event_count"])
    st.caption(f"{meta.get('train_window_count', 0)} training windows, seed {meta.get('seed')}, "
               f"{len(meta['feature_names'])} features")
    with st.expander("Training sanity metrics"):
        st.json(meta.get("train_metrics", {}))
    base = pd.DataFrame(meta.get("feature_baseline", []))
    if not base.empty:
        with st.expander("Training baseline (mean and std per feature)"):
            st.dataframe(base, use_container_width=True)


def _show_evaluate(start: str, end: str) -> None:
    st.subheader("Evaluate")
    st.caption("Uses ground truth labels (evaluation only). Threshold: anomaly 0.5.")
    if st.button("Evaluate on this time range"):
        with st.spinner("Scoring windows and computing metrics..."):
            try:
                result = _call("POST", "/v1/evaluate", {"time_range": {"start": start, "end": end}}, timeout=300.0)
            except RuntimeError as exc:
                st.error(str(exc))
                return
        cols = st.columns(5)
        for col, key in zip(cols, ["precision", "recall", "f1", "pr_auc", "false_positives_per_host_day"]):
            col.metric(key.replace("_", " "), f"{result.get(key, 0):.3f}")
        st.caption(f"TP {result.get('tp')}, FP {result.get('fp')}, FN {result.get('fn')}, "
                   f"{result.get('n_windows')} windows")
        st.markdown(f"Logged to MLflow. [Open MLflow UI]({MLFLOW_UI})")


def _show_zscores(start: str, end: str) -> None:
    st.subheader("Top anomalous windows and feature z-scores")
    if not st.button("Score windows in this time range"):
        return
    try:
        data = _call("POST", "/v1/windows", {"time_range": {"start": start, "end": end}}, timeout=120.0)
    except RuntimeError as exc:
        st.error(str(exc))
        return
    items = sorted(data.get("items", []), key=lambda w: w["anomaly"], reverse=True)[:15]
    if not items:
        st.info("No windows in this range.")
        return
    st.dataframe(pd.DataFrame([{"host": w["host"], "from": w["ts_first"], "anomaly": w["anomaly"],
                                "isolation forest": w["anomaly_if"], "sequence": w["anomaly_seq"],
                                "uncertainty": w["uncertainty"], "cluster": w["cluster_id"],
                                "events": len(w["event_ids"])} for w in items]), use_container_width=True)
    rows = [{"window": f"{w['host']} {w['ts_first'][11:16]}", "feature": f["name"], "z": f["z"]}
            for w in items[:8] for f in w["top_features"]]
    if rows:
        frame = pd.DataFrame(rows).pivot_table(index="window", columns="feature", values="z", fill_value=0.0)
        st.bar_chart(frame)


def main() -> None:
    try:
        st.set_page_config(page_title="Model and Data", layout="wide")
    except Exception:  # noqa: BLE001 - already configured by the app shell
        pass
    st.title("Model and Data")
    _show_meta()
    c1, c2 = st.columns(2)
    start = c1.text_input("Start (UTC)", DEFAULT_START)
    end = c2.text_input("End (UTC)", DEFAULT_END)
    _show_evaluate(start, end)
    _show_zscores(start, end)


try:
    main()
except Exception as exc:  # noqa: BLE001 - the page must never show a traceback
    st.error(f"Page error: {type(exc).__name__}")
