"""Shared dashboard widgets (spec 11.1). Owner: Lead. Plain Streamlit, no custom JavaScript."""
from __future__ import annotations

from typing import Optional

import streamlit as st

SEVERITY = {1: ("Info", "#6b7280"), 2: ("Low", "#2563eb"), 3: ("Medium", "#ca8a04"),
            4: ("High", "#ea580c"), 5: ("Critical", "#dc2626")}


def severity_label(severity: int) -> str:
    return SEVERITY.get(int(severity), SEVERITY[1])[0]


def confidence_band(confidence: float) -> str:
    return "high" if confidence >= 70 else "medium" if confidence >= 40 else "low"


def severity_badge(severity: int) -> None:
    name, color = SEVERITY.get(int(severity), SEVERITY[1])
    st.markdown(f":{_streamlit_color(color)}[**{name}**]")


def _streamlit_color(hex_color: str) -> str:
    return {"#6b7280": "gray", "#2563eb": "blue", "#ca8a04": "orange", "#ea580c": "orange",
            "#dc2626": "red"}.get(hex_color, "gray")


def confidence_meter(confidence: float, label: str = "Confidence") -> None:
    value = min(max(float(confidence), 0.0), 100.0)
    st.metric(label, f"{value:.0f} / 100", confidence_band(value))
    st.progress(value / 100.0)


def rationale_card(rationale: Optional[str]) -> None:
    with st.container(border=True):
        st.caption("Why this ranks here")
        st.write(rationale or "No rationale recorded.")


def health_badge(name: str, ok: Optional[bool], detail: str = "") -> None:
    mark = "OK" if ok else ("DOWN" if ok is False else "n/a")
    color = "green" if ok else ("red" if ok is False else "gray")
    st.markdown(f":{color}[**{mark}**] {name}" + (f" ({detail})" if detail else ""))
