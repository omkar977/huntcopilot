"""Page 1: Alert Queue. Findings ranked by confidence plus the raw rule alerts (owner: M2).

Calls only api_client. Every API error is shown with st.error, never as a traceback.
"""
import streamlit as st

try:
    import api_client
except ImportError:  # the shell (app.py, api_client.py) is delivered by the Lead
    api_client = None

from hc_hunt import views

FINDING_LIST = ("list_findings", "get_findings", "findings")
ALERT_LIST = ("list_alerts", "get_alerts", "alerts")


def _fetch(names, **kwargs):
    if api_client is None:
        st.error("The dashboard API client (api_client.py) is not available yet.")
        return None
    try:
        return views.items_of(views.call_api(api_client, names, **kwargs))
    except Exception as exc:  # noqa: BLE001 - shown to the analyst, never a traceback
        st.error(f"Could not load data from the API: {exc}")
        return None


def _detail(finding):
    scores = finding.get("scores") or {}
    confidence = float(scores.get("confidence", 0))
    left, right = st.columns([1, 2])
    with left:
        st.metric("Confidence", f"{confidence:.0f} / 100", views.confidence_label(confidence))
        st.progress(min(max(confidence / 100.0, 0.0), 1.0))
        st.write("Hosts:", ", ".join(finding.get("hosts") or []) or "-")
        st.write("Users:", ", ".join(finding.get("users") or []) or "-")
        st.write("Stages:", ", ".join(finding.get("stages_found") or []) or "-")
        st.write("Techniques:", ", ".join(finding.get("technique_ids") or []) or "-")
    with right:
        st.subheader("Score components")
        st.bar_chart(views.score_components(finding))
    st.subheader("Rationale")
    st.info(finding.get("rationale") or "No rationale available.")
    features = views.feature_rows(finding)
    if features:
        st.subheader("Top features")
        st.dataframe(features, use_container_width=True)


def _findings_tab():
    left, right = st.columns(2)
    with left:
        min_conf = st.slider("Minimum confidence", 0, 100, 0)
    with right:
        host = st.text_input("Host contains", value="")
    findings = _fetch(FINDING_LIST, min_confidence=min_conf, host=host.strip() or None, limit=200)
    if findings is None:
        return
    if not findings:
        st.info("No findings match. Run a hunt on the Hunt Builder page first.")
        return
    st.dataframe(views.finding_rows(findings), use_container_width=True)
    options = {views.finding_option_label(f): f for f in findings}
    chosen = st.selectbox("Finding detail", list(options))
    if chosen:
        _detail(options[chosen])


def _alerts_tab():
    cols = st.columns(3)
    with cols[0]:
        status = st.selectbox("Status", ["", "new", "triaged", "closed"])
    with cols[1]:
        rule_id = st.text_input("Rule id (for example HC-001)", value="")
    with cols[2]:
        host = st.text_input("Alert host", value="")
    alerts = _fetch(ALERT_LIST, status=status or None, rule_id=rule_id.strip() or None,
                    host=host.strip() or None, limit=500)
    if alerts is None:
        return
    if not alerts:
        st.info("No alerts yet. Start the detector and load telemetry.")
        return
    st.caption(f"{len(alerts)} alert(s)")
    st.dataframe(views.alert_rows(alerts), use_container_width=True)


def render():
    try:
        st.set_page_config(page_title="Alert Queue", layout="wide")
    except Exception:  # noqa: BLE001 - already configured by another page
        pass
    st.title("Alert Queue")
    findings_tab, alerts_tab = st.tabs(["Findings", "Rule alerts"])
    with findings_tab:
        _findings_tab()
    with alerts_tab:
        _alerts_tab()


if __name__ == "__main__":
    render()
