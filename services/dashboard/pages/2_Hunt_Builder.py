"""Page 2: Hunt Builder (owner M4). Calls only api_client; never talks to services directly."""
import json

import streamlit as st

try:
    import api_client
except ImportError:  # shown as a readable error instead of a traceback
    api_client = None

EXAMPLES = [
    "Find possible lateral movement after a suspicious PowerShell execution.",
    "Look for credential dumping from LSASS on servers.",
    "Hunt for C2 beaconing to external hosts.",
    "Check for phishing macros that launched PowerShell.",
]


def _call(name, *args, **kwargs):
    """Call api_client.<name>; show a readable error and return None on any failure."""
    fn = getattr(api_client, name, None)
    if fn is None:
        st.error(f"api_client.{name} is missing. Ask the Lead to add it.")
        return None
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # never crash the page, never show a traceback
        st.error(str(exc)[:500])
        return None


def _step_rows(plan):
    return [{"step": s["step_id"], "stage": s.get("stage", ""), "description": s["description"],
             "depends_on": ", ".join(s.get("depends_on", [])),
             "filters": "; ".join(f"{c['field']} {c['op']} {c['value']}" for c in s["query"]["filters"])}
            for s in plan.get("steps", [])]


def _show_plan(plan):
    v = plan.get("validation", {})
    c1, c2, c3 = st.columns(3)
    c1.metric("Source", plan.get("source", "?"))
    c2.metric("Validation", "passed" if v.get("ok") else "failed")
    c3.metric("Template", plan.get("template") or "-")
    st.markdown(f"**Hypothesis:** {plan.get('hypothesis', '')}")
    st.caption("Expected stages: " + ", ".join(plan.get("expected_stages", [])))
    st.dataframe(_step_rows(plan))
    for w in v.get("warnings", []):
        st.warning(w)
    for e in v.get("errors", []):
        st.error(e)
    with st.expander("Plan JSON"):
        st.code(json.dumps(plan, indent=2), language="json")


def _show_run(run):
    st.subheader("Run result")
    st.caption(f"Run {run.get('run_id', '')[:12]} is {run.get('status')}")
    if run.get("error"):
        st.error(run["error"])
    st.dataframe([{"step": r["step_id"], "events": r["event_count"], "hosts": ", ".join(r["hosts"]),
                   "ms": r["duration_ms"]} for r in run.get("step_results", [])])
    findings = run.get("findings", [])
    if not findings:
        st.info("No findings for this hunt.")
    for f in findings:
        st.markdown(f"**Confidence {f['scores']['confidence']:.0f}** on {', '.join(f['hosts'])} "
                    f"(finding `{f['finding_id'][:12]}`). Open Response Approvals or Case Export to continue.")
        st.write(f["rationale"])


st.set_page_config(page_title="Hunt Builder", layout="wide")
st.title("Hunt Builder")
if api_client is None:
    st.error("api_client module not found. Run the dashboard from services/dashboard.")
    st.stop()

st.write("Describe what you want to hunt in plain English, or pick an example.")


def _use_example(text):
    """Button callback: runs before the text box is drawn, so the box shows the example."""
    st.session_state["intent_box"] = text


cols = st.columns(len(EXAMPLES))
for i, text in enumerate(EXAMPLES):
    cols[i].button(f"Example {i + 1}", key=f"ex{i}", on_click=_use_example, args=(text,), help=text)
intent = st.text_area("Hunt request", max_chars=500, key="intent_box")

if st.button("Generate plan"):
    plan = _call("create_hunt", intent.strip()) if len(intent.strip()) >= 3 else None
    if plan is None and len(intent.strip()) < 3:
        st.warning("Type at least 3 characters.")
    st.session_state["plan"] = plan
    st.session_state["run"] = None

plan = st.session_state.get("plan")
if plan:
    _show_plan(plan)
    if st.button("Run hunt"):
        with st.spinner("Running hunt..."):
            st.session_state["run"] = _call("run_hunt", plan["plan_id"])
if st.session_state.get("run"):
    _show_run(st.session_state["run"])