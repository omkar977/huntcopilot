"""Page 4: Response Approvals (owner M4). Human approval of simulated containment actions."""
import streamlit as st

try:
    import api_client
except ImportError:
    api_client = None


def _call(name, *args, **kwargs):
    """Call api_client.<name>; show a readable error and return None on any failure."""
    fn = getattr(api_client, name, None)
    if fn is None:
        st.error(f"api_client.{name} is missing. Ask the Lead to add it.")
        return None
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        st.error(str(exc)[:500])
        return None


def _decide(prop, approver, confirm):
    pid = prop["proposal_id"]
    a, r = st.columns(2)
    if a.button("Approve", key=f"ap_{pid}"):
        if len(approver.strip()) < 3:
            st.warning("Enter your name (at least 3 characters).")
        elif not confirm:
            st.warning("Tick the confirmation box first.")
        else:
            out = _call("approve_proposal", pid, approver.strip(), True)
            if out:
                st.success(f"Status: {out['status']}. {out.get('result', '')}")
    if r.button("Reject", key=f"rj_{pid}"):
        if len(approver.strip()) < 3:
            st.warning("Enter your name (at least 3 characters).")
        else:
            out = _call("reject_proposal", pid, approver.strip(), "rejected in dashboard")
            if out:
                st.success(f"Status: {out['status']}")


st.set_page_config(page_title="Response Approvals", layout="wide")
st.title("Response Approvals")
if api_client is None:
    st.error("api_client module not found. Run the dashboard from services/dashboard.")
    st.stop()
st.caption("Every action here is a simulation. Nothing runs on a real system.")

verify = _call("verify_audit")
if verify is not None:
    if verify.get("ok"):
        st.success("Audit chain verified")
    else:
        st.error(f"Audit chain BROKEN at entry {verify.get('first_bad_seq')}")

approver = st.text_input("Approver name", value="", max_chars=100)
confirm = st.checkbox("I confirm I reviewed this action and approve it")
st.subheader("Pending proposals")
pending = _call("list_proposals", "pending")
items = (pending or {}).get("items", [])
if not items:
    st.info("No pending proposals.")
for prop in items:
    st.markdown(f"**{prop['action']}** on `{prop['target']}` (finding `{prop['finding_id'][:12]}`)")
    st.write(prop["justification"])
    _decide(prop, approver, confirm)

st.subheader("Simulated state")
state = _call("get_state") or {}
for key in ("host_state", "blocked_ips", "disabled_accounts", "killed_processes"):
    st.caption(key)
    st.dataframe(state.get(key, []))

with st.expander("Audit log (latest entries)"):
    audit = _call("get_audit", 50)
    st.dataframe((audit or {}).get("items", []))
