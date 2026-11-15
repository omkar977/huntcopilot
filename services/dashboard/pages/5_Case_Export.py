"""Page 5: Case Export (owner M4)."""
import json

import streamlit as st

try:
    import api_client
except ImportError:
    api_client = None
try:
    import case_pdf
except ImportError:  # reportlab missing: the PDF button is hidden, the other exports still work
    case_pdf = None


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


st.set_page_config(page_title="Case Export", layout="wide")
st.title("Case Export")
if api_client is None:
    st.error("api_client module not found. Run the dashboard from services/dashboard.")
    st.stop()

found = _call("list_findings", 0, "") or {}
items = found.get("items", [])
if not items:
    st.info("No findings yet. Run a hunt first.")
    st.stop()

labels = {f"{f['scores']['confidence']:.0f} | {', '.join(f['hosts'])} | {f['finding_id'][:12]}": f["finding_id"]
          for f in items}
choice = st.selectbox("Finding", list(labels))
fid = labels[choice]
md = _call("export_case", fid, "md")
js = _call("export_case", fid, "json")
if md:
    st.markdown("Preview")
    st.markdown(md if isinstance(md, str) else str(md))
    st.download_button("Download Markdown", data=md, file_name=f"case_{fid[:12]}.md", mime="text/markdown")
if js is not None:
    data = js if isinstance(js, str) else json.dumps(js, indent=2)
    st.download_button("Download JSON", data=data, file_name=f"case_{fid[:12]}.json", mime="application/json")
if isinstance(js, dict) and case_pdf is not None:
    try:
        st.download_button("Download PDF incident report", data=case_pdf.build_pdf(js),
                           file_name=f"incident_report_{fid[:12]}.pdf", mime="application/pdf")
    except Exception as exc:  # never show a traceback
        st.error(f"Could not build the PDF: {str(exc)[:300]}")
elif case_pdf is None:
    st.caption("PDF export needs the reportlab package (rebuild the dashboard image).")
