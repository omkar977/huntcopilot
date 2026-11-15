"""HuntCopilot dashboard shell (spec 11.1). Owner: Lead. Run: streamlit run services/dashboard/app.py"""
import os

import streamlit as st

import api_client
import ui

st.set_page_config(page_title="HuntCopilot", layout="wide")

SERVICES = {
    "ml": os.getenv("HC_ML_URL", "http://ml:8100"),
    "detector": os.getenv("HC_DETECTOR_URL", "http://detector:8200"),
    "generator": os.getenv("HC_GENERATOR_URL", "http://generator:8300"),
}


@st.cache_data(ttl=10, show_spinner=False)
def _probe(name: str, url: str):
    try:
        data = api_client.service_health(url) if name != "api" else api_client.health()
        return True, str(data.get("status", "ok"))
    except api_client.ApiError as exc:
        return False, str(exc)[:60]


with st.sidebar:
    st.title("HuntCopilot")
    st.caption("Synthetic data only. No real response actions.")
    st.subheader("Service health")
    ok, detail = _probe("api", api_client.api_url())
    ui.health_badge("api", ok, "" if ok else detail)
    for svc, url in SERVICES.items():
        ok, detail = _probe(svc, url)
        ui.health_badge(svc, ok, "" if ok else detail)
    if st.button("Refresh"):
        st.cache_data.clear()
        st.rerun()

st.title("HuntCopilot")
st.write("AI-assisted threat hunting on synthetic telemetry. Pick a page in the sidebar.")

try:
    stats = api_client.get_stats()
    cols = st.columns(4)
    for col, key in zip(cols, ("events", "alerts", "findings", "proposals")):
        col.metric(key.capitalize(), stats.get(key, "-"))
except api_client.ApiError as exc:
    st.error(f"Could not load stats: {exc}")
