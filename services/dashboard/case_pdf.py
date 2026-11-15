"""Incident report PDF in a CERT-style layout (spec 5.10 appendix). Owner: Lead.

build_pdf(case) takes the case JSON of GET /v1/cases/{finding_id}/export and returns PDF bytes.
Uses reportlab only. All data is synthetic: the report says so on every page.
The layout follows the usual national-CERT incident report fields (incident time, affected systems,
incident type, severity, actions taken). It is NOT an official submission and carries no agency branding.
"""
from __future__ import annotations

import io
import math
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

NAVY = colors.HexColor("#14284b")
GREY = colors.HexColor("#5b6472")
LIGHT = colors.HexColor("#eef1f6")
RULE = colors.HexColor("#c5ccd8")
SEV_COLOR = {"Critical": "#b42318", "High": "#d9480f", "Medium": "#b7791f", "Low": "#2b6cb0"}

INCIDENT_TYPES = {
    "initial_access": "Phishing / malicious attachment",
    "execution": "Malicious code execution (PowerShell)",
    "lateral_movement": "Unauthorised access (lateral movement)",
    "credential_access": "Credential theft / account compromise",
    "c2": "Command-and-control communication",
}
STAGE_ORDER = ["initial_access", "execution", "credential_access", "lateral_movement", "c2"]
FOOTER = "SYNTHETIC DATA. No real systems or actions."


def _t(value: Any, limit: int = 0) -> str:
    """Escaped, latin-1 safe text for Paragraph."""
    text = "" if value is None else str(value)
    text = text.encode("latin-1", "replace").decode("latin-1")
    if limit and len(text) > limit:
        text = text[: limit - 3] + "..."
    return escape(text)


def _ts(value: Any) -> str:
    if not value:
        return "-"
    text = str(value).replace("T", " ").replace("Z", " UTC")
    return text[:23] if "UTC" not in text else text.split(" UTC")[0][:19] + " UTC"


def severity(scores: Dict[str, Any]) -> str:
    conf = float(scores.get("confidence", 0))
    crit = float(scores.get("criticality", 0))
    if conf >= 85 and crit >= 0.8:
        return "Critical"
    if conf >= 70:
        return "High"
    if conf >= 40:
        return "Medium"
    return "Low"


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.2, leading=12.6),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontName="Helvetica", fontSize=7.8, leading=10, textColor=GREY),
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontName="Helvetica", fontSize=8.4, leading=10.8),
        "cellb": ParagraphStyle("cellb", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.4, leading=10.8, textColor=NAVY),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=11.5, leading=14,
                             textColor=NAVY, spaceBefore=10, spaceAfter=4),
        "title": ParagraphStyle("title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24,
                                textColor=colors.white, alignment=0),
        "sub": ParagraphStyle("sub", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5, leading=12,
                              textColor=colors.HexColor("#d6deee")),
        "center": ParagraphStyle("center", parent=base["BodyText"], alignment=TA_CENTER, fontSize=8, textColor=GREY),
    }


def _kv_table(rows: List[Tuple[str, str]], st: Dict[str, ParagraphStyle], widths=(4.2 * cm, 12.8 * cm)) -> Table:
    data = [[Paragraph(_t(k), st["cellb"]), Paragraph(v, st["cell"])] for k, v in rows]
    tbl = Table(data, colWidths=widths)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5)]))
    return tbl


def _grid_table(header: List[str], rows: List[List[str]], widths: List[float], st: Dict[str, ParagraphStyle]) -> Table:
    data = [[Paragraph(_t(h), ParagraphStyle("th", parent=st["cellb"], textColor=colors.white)) for h in header]]
    data += [[Paragraph(c, st["cell"]) for c in r] for r in rows] or [[Paragraph("none", st["cell"])] + [""] * (len(header) - 1)]
    tbl = Table(data, colWidths=widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return tbl


def _score_bars(scores: Dict[str, Any]) -> Drawing:
    """Four horizontal bars (anomaly, coverage, criticality, certainty) and the final score."""
    rows = [("Anomaly strength", float(scores.get("anomaly", 0)), "weight 0.35"),
            ("Evidence coverage", float(scores.get("coverage", 0)), "weight 0.25"),
            ("Asset criticality", float(scores.get("criticality", 0)), "weight 0.20"),
            ("Certainty (1 - uncertainty)", 1.0 - float(scores.get("uncertainty", 0)), "weight 0.20")]
    d = Drawing(17 * cm, 4.2 * cm)
    x0, w, h = 4.6 * cm, 9.2 * cm, 0.5 * cm
    for i, (label, val, weight) in enumerate(rows):
        y = 3.5 * cm - i * 0.85 * cm
        d.add(String(0, y + 0.12 * cm, label, fontName="Helvetica", fontSize=8.5, fillColor=colors.black))
        d.add(Rect(x0, y, w, h, fillColor=LIGHT, strokeColor=RULE, strokeWidth=0.4))
        d.add(Rect(x0, y, w * max(0.0, min(1.0, val)), h, fillColor=NAVY, strokeColor=None))
        d.add(String(x0 + w + 0.3 * cm, y + 0.12 * cm, f"{val:.2f}  ({weight})", fontName="Helvetica", fontSize=8, fillColor=GREY))
    return d


def _in(edge: Dict[str, Any], hosts: Optional[List[str]]) -> bool:
    """Keep an edge only when both ends are affected hosts (benign clients of a server are left out)."""
    return hosts is None or (str(edge["src"])[5:] in hosts and str(edge["dst"])[5:] in hosts)


def _chain_figure(chain: Dict[str, Any], hosts: Optional[List[str]] = None) -> Optional[Drawing]:
    """Host-to-host graph on a circle. Returns None when there are fewer than 2 hosts linked."""
    nodes = {n["id"]: n for n in chain.get("nodes", [])}
    pairs: Dict[Tuple[str, str], int] = {}
    for e in chain.get("edges", []):
        if str(e["src"]).startswith("host:") and str(e["dst"]).startswith("host:") and e["src"] != e["dst"] \
                and _in(e, hosts):
            pairs[(e["src"], e["dst"])] = pairs.get((e["src"], e["dst"]), 0) + 1
    hosts = sorted({h for p in pairs for h in p})
    if len(hosts) < 2:
        return None
    width, height = 17 * cm, 8.2 * cm
    cx, cy, rx, ry = width / 2, height / 2, 6.0 * cm, 2.9 * cm
    pos = {}
    for i, h in enumerate(hosts):
        ang = 2 * math.pi * i / len(hosts) - math.pi / 2
        pos[h] = (cx + rx * math.cos(ang), cy - ry * math.sin(ang))
    d = Drawing(width, height)
    bw, bh = 2.3 * cm, 0.7 * cm
    for (a, b), n in pairs.items():
        (x1, y1), (x2, y2) = pos[a], pos[b]
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy) or 1.0
        ux, uy = dx / dist, dy / dist
        sx, sy = x1 + ux * bw * 0.55, y1 + uy * bh * 0.9
        ex, ey = x2 - ux * bw * 0.55, y2 - uy * bh * 0.9
        d.add(Line(sx, sy, ex, ey, strokeColor=GREY, strokeWidth=0.7))
        px, py = -uy, ux
        d.add(Polygon([ex, ey, ex - ux * 0.28 * cm + px * 0.12 * cm, ey - uy * 0.28 * cm + py * 0.12 * cm,
                       ex - ux * 0.28 * cm - px * 0.12 * cm, ey - uy * 0.28 * cm - py * 0.12 * cm],
                      fillColor=GREY, strokeColor=None))
    for h, (x, y) in pos.items():
        risk = float(nodes.get(h, {}).get("risk", 0.2))
        fill = colors.HexColor("#b42318") if risk >= 0.7 else colors.HexColor("#d9480f") if risk >= 0.45 else colors.HexColor("#2b6cb0")
        d.add(Rect(x - bw / 2, y - bh / 2, bw, bh, fillColor=fill, strokeColor=None, rx=3, ry=3))
        d.add(String(x, y - 0.1 * cm, h[5:], fontName="Helvetica-Bold", fontSize=8.5, fillColor=colors.white, textAnchor="middle"))
    return d


def _hhmm_rows(chain: Dict[str, Any], hosts: Optional[List[str]] = None, limit: int = 30) -> List[List[str]]:
    rows = []
    for e in sorted(chain.get("edges", []), key=lambda e: (str(e["ts"]), e["src"], e["dst"])):
        if str(e["src"]).startswith("host:") and str(e["dst"]).startswith("host:") and _in(e, hosts):
            rows.append([_t(_ts(e["ts"])), _t(e["src"][5:]), _t(e["dst"][5:]), _t(e["kind"])])
    return rows[:limit]


def _header(st: Dict[str, ParagraphStyle], case_ref: str, sev: str) -> Table:
    left = [Paragraph("INCIDENT REPORT", st["title"]),
            Paragraph("CERT-style format &nbsp;|&nbsp; HuntCopilot hunt case", st["sub"])]
    right = Paragraph(f'<font color="white" size="9">SEVERITY</font><br/><font color="white" size="17"><b>{_t(sev.upper())}</b></font>',
                      ParagraphStyle("sv", parent=st["body"], alignment=TA_CENTER, leading=20))
    tbl = Table([[left, right]], colWidths=[12.2 * cm, 4.8 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), NAVY), ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(SEV_COLOR[sev])),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12)]))
    return tbl


def build_pdf(case: Dict[str, Any]) -> bytes:
    f = case["finding"]
    scores = f["scores"]
    st = _styles()
    sev = severity(scores)
    ref = f"HC-{str(case.get('case_id') or f['finding_id'])[:12].upper()}"
    stages = [s for s in STAGE_ORDER if s in f.get("stages_found", [])] + \
             [s for s in f.get("stages_found", []) if s not in STAGE_ORDER]
    types = "; ".join(INCIDENT_TYPES.get(s, s) for s in stages) or "Suspicious activity (unclassified)"
    proposals = case.get("proposals", [])
    decided = [p for p in proposals if p.get("status") in ("executed", "approved", "rejected", "failed")]
    status = "Containment decided (simulated)" if decided else ("Containment pending approval" if proposals else "Under analysis")
    ext_ips = sorted({n["label"] for n in f["chain"].get("nodes", []) if n.get("type") == "ip"
                      and not str(n["label"]).startswith(("10.", "192.168.", "172."))})
    ext_ips = sorted(set(ext_ips) | {a["target"] for a in f.get("recommended_actions", []) if a.get("action") == "block_ip"})
    story: List[Any] = [_header(st, ref, sev), Spacer(1, 8)]

    story.append(_kv_table([
        ("Report reference", _t(ref)), ("Report generated", _t(_ts(case.get("generated_at")))),
        ("Reporting analyst", _t(case.get("analyst") or "not recorded")),
        ("Classification", "TLP:AMBER (exercise data)"), ("Status", _t(status))], st))

    story.append(Paragraph("1. Incident summary", st["h1"]))
    story.append(_kv_table([
        ("Incident window", f"{_t(_ts(f['ts_first']))} to {_t(_ts(f['ts_last']))}"),
        ("Incident type", _t(types)), ("Severity", f"<b>{_t(sev)}</b>"),
        ("Hunt confidence", f"{float(scores['confidence']):.0f} of 100"),
        ("Affected systems", _t(", ".join(f["hosts"]))),
        ("Affected accounts", _t(", ".join(f.get("users", [])) or "none identified")),
        ("Attack stages observed", _t(" > ".join(stages) or "none")),
        ("MITRE ATT&CK techniques", _t(", ".join(f.get("technique_ids", [])) or "none")),
        ("Detection source", "Detection rules and ML anomaly model, correlated by a hypothesis-driven hunt"),
        ("Alerts / evidence events", f"{len(f.get('alert_ids', []))} rule alerts, {len(f.get('event_ids', []))} evidence events")], st))

    story.append(Paragraph("2. Description", st["h1"]))
    intent = (case.get("hunt") or {}).get("intent_text") or "not recorded"
    plan = (case.get("hunt") or {}).get("plan") or {}
    story.append(Paragraph(f"<b>Hunt request:</b> {_t(intent)}", st["body"]))
    if plan.get("hypothesis"):
        story.append(Paragraph(f"<b>Hypothesis:</b> {_t(plan['hypothesis'])}", st["body"]))
    story.append(Spacer(1, 3))
    story.append(Paragraph(f"<b>Assessment:</b> {_t(f['rationale'])}", st["body"]))

    story.append(Paragraph("3. Confidence breakdown", st["h1"]))
    story.append(KeepTogether([_score_bars(scores), Paragraph(
        "Confidence = 100 x (0.35 x anomaly + 0.25 x coverage + 0.20 x criticality + 0.20 x certainty). "
        "It ranks leads for a human analyst and is not a verdict.", st["small"])]))
    feats = f.get("top_features", [])[:3]
    if feats:
        story.append(Spacer(1, 4))
        story.append(_grid_table(["Top anomalous feature", "Value", "z-score vs normal"],
                                 [[_t(x["name"]), _t(f"{x['value']:.2f}"), _t(f"{x['z']:.1f}")] for x in feats],
                                 [8 * cm, 4 * cm, 5 * cm], st))

    story.append(Paragraph("4. Attack chain", st["h1"]))
    fig = _chain_figure(f["chain"], f["hosts"])
    if fig is not None:
        story.append(fig)
        story.append(Paragraph("Arrows show host-to-host activity between the affected systems. Colour: red high risk, orange elevated, blue lower.", st["small"]))
    rows = _hhmm_rows(f["chain"], f["hosts"])
    story.append(Spacer(1, 4))
    story.append(_grid_table(["Time (UTC)", "From", "To", "Activity"], rows, [5 * cm, 3.6 * cm, 3.6 * cm, 4.8 * cm], st))
    total = sum(1 for e in f["chain"].get("edges", [])
                if str(e["src"]).startswith("host:") and str(e["dst"]).startswith("host:") and _in(e, f["hosts"]))
    if total > len(rows):
        story.append(Paragraph(f"Showing {len(rows)} of {total} host-to-host events. Full list: JSON export.", st["small"]))

    story.append(Paragraph("5. Indicators", st["h1"]))
    story.append(_kv_table([
        ("Hosts", _t(", ".join(f["hosts"]))), ("Accounts", _t(", ".join(f.get("users", [])) or "none")),
        ("External IP addresses", _t(", ".join(ext_ips) or "none in the chain")),
        ("Rule alert ids", _t(", ".join(a[:10] for a in f.get("alert_ids", [])[:12]) or "none"))], st))

    story.append(Paragraph("6. Response actions", st["h1"]))
    story.append(Paragraph("Every disruptive action requires a named human approval. Actions below are simulated.", st["small"]))
    act_rows = []
    by_target = {(p["action"], p["target"]): p for p in proposals}
    for a in f.get("recommended_actions", []):
        p = by_target.get((a["action"], a["target"]))
        state = (p["status"] if p else "not proposed") + (f" by {p['decided_by']}" if p and p.get("decided_by") else "")
        act_rows.append([_t(a["action"]), _t(a["target"]), _t(state), _t(a["rationale"], 150)])
    story.append(_grid_table(["Action", "Target", "Decision", "Reason"], act_rows, [2.8 * cm, 3 * cm, 3.4 * cm, 7.8 * cm], st))

    story.append(Paragraph("7. Audit trail", st["h1"]))
    audit = case.get("audit_entries", [])
    story.append(_grid_table(["#", "Time (UTC)", "Actor", "Event", "Hash (first 12)"],
                             [[_t(a.get("seq")), _t(_ts(a.get("ts"))), _t(a.get("actor")), _t(a.get("action")),
                               _t(str(a.get("hash", ""))[:12])] for a in audit[:25]],
                             [1.2 * cm, 4.2 * cm, 3.2 * cm, 4.4 * cm, 4 * cm], st))
    story.append(Paragraph("Entries are chained with SHA-256 (each entry includes the previous hash), so any edit is detectable.", st["small"]))

    story.append(Paragraph("8. Notes and limitations", st["h1"]))
    for n in case.get("notes", []):
        story.append(Paragraph("- " + _t(n), st["body"]))
    story.append(Paragraph("- Rules and test data were written from the same specification, so detection results are optimistic.", st["body"]))
    story.append(Spacer(1, 14))
    sign = Table([[Paragraph("Prepared by<br/><br/>____________________<br/>Analyst", st["cell"]),
                   Paragraph("Reviewed by<br/><br/>____________________<br/>Incident lead", st["cell"]),
                   Paragraph("Date<br/><br/>____________________<br/>&nbsp;", st["cell"])]], colWidths=[5.6 * cm] * 3)
    story.append(KeepTogether([sign]))

    def _page(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(RULE)
        canvas.line(2 * cm, 1.55 * cm, A4[0] - 2 * cm, 1.55 * cm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(GREY)
        canvas.drawString(2 * cm, 1.1 * cm, f"{ref}  |  TLP:AMBER (exercise)  |  {FOOTER}")
        canvas.drawRightString(A4[0] - 2 * cm, 1.1 * cm, f"Page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm, bottomMargin=2.1 * cm,
                            title=f"Incident report {ref}", author="HuntCopilot", subject="Synthetic data exercise")
    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return buf.getvalue()

