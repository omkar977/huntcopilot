"""Page 3: Attack Chain. Pick a finding and see its host-to-host attack graph (owner: M2).

Calls only api_client. Every API error is shown with st.error, never as a traceback.
"""
import streamlit as st

try:
    import api_client
except ImportError:  # the shell (app.py, api_client.py) is delivered by the Lead
    api_client = None

from hc_hunt import chain_to_dot, views

FINDING_LIST = ("list_findings", "get_findings", "findings")


def _load_findings():
    if api_client is None:
        st.error("The dashboard API client (api_client.py) is not available yet.")
        return None
    try:
        return views.items_of(views.call_api(api_client, FINDING_LIST, min_confidence=0, limit=200))
    except Exception as exc:  # noqa: BLE001 - shown to the analyst, never a traceback
        st.error(f"Could not load findings from the API: {exc}")
        return None


def _show_chain(finding):
    try:
        chain = views.chain_of(finding)
    except Exception as exc:  # noqa: BLE001
        st.error(f"This finding has a chain that cannot be displayed: {exc}")
        return
    if not chain.edges:
        st.info("This finding has no attack-chain edges.")
        return
    st.caption(f"{len(chain.nodes)} nodes, {len(chain.edges)} edges, "
               f"{views.host_edge_count(chain)} host-to-host")
    st.graphviz_chart(chain_to_dot(chain), use_container_width=True)
    st.subheader("Legend")
    legend = "  ".join(f"<span style='background:{row['colour']};padding:2px 10px'>&nbsp;</span> {row['meaning']}"
                       for row in views.legend_rows())
    st.markdown(legend, unsafe_allow_html=True)
    st.caption("Boxes are hosts, ellipses processes, diamonds IP addresses, hexagons domains.")
    st.subheader("Edges")
    st.dataframe(views.edge_rows(chain), use_container_width=True)


def render():
    try:
        st.set_page_config(page_title="Attack Chain", layout="wide")
    except Exception:  # noqa: BLE001 - already configured by another page
        pass
    st.title("Attack Chain")
    findings = _load_findings()
    if findings is None:
        return
    if not findings:
        st.info("No findings yet. Run a hunt on the Hunt Builder page first.")
        return
    options = {views.finding_option_label(f): f for f in findings}
    chosen = st.selectbox("Finding", list(options))
    if chosen:
        _show_chain(options[chosen])


if __name__ == "__main__":
    render()
