"""Self-contained executive PDF and machine-readable JSON exports."""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def pdf_report(payload: dict) -> bytes:
    out = BytesIO()
    doc = SimpleDocTemplate(out, pagesize=(612, 792), rightMargin=46,
                            leftMargin=46, topMargin=42, bottomMargin=44,
                            title="SignalHarbor Security Posture Report")
    st = getSampleStyleSheet()
    st.add(ParagraphStyle(name="SHtitle", parent=st["Title"], fontName="Helvetica-Bold",
                          fontSize=21, textColor=colors.HexColor("#152a43"), spaceAfter=16, alignment=TA_LEFT))
    st.add(ParagraphStyle(name="SHsection", parent=st["Heading2"], fontSize=12,
                          textColor=colors.HexColor("#126a8a"), spaceBefore=17, spaceAfter=8))
    st.add(ParagraphStyle(name="SHsmall", parent=st["BodyText"], fontSize=8.5, leading=12,
                          textColor=colors.HexColor("#344357"), spaceAfter=4))
    st.add(ParagraphStyle(name="SHcell", parent=st["BodyText"], fontSize=7.6, leading=10,
                          textColor=colors.HexColor("#293a4b")))
    story = [Paragraph("SignalHarbor", st["SHtitle"]),
             Paragraph("Security posture & incident intelligence | executive snapshot", st["SHsmall"]),
             Paragraph("Generated " + datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC"), st["SHsmall"]),
             Spacer(1, 16)]
    overview = payload["overview"]
    stats = ["Assets monitored", "Latest assessments", "Open findings", "Average posture score"]
    vals = [str(overview["assets_count"]), str(overview["assessments_count"]),
            str(overview["open_findings"]), f'{overview["average_score"]}/100']
    rows = [[Paragraph(x, st["SHcell"]) for x in stats], [Paragraph(v, st["SHsection"]) for v in vals]]
    table = Table(rows, colWidths=[130] * 4, rowHeights=[26, 43])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#eff5f9")),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("LINEBELOW", (0,-1), (-1,-1), 0.8, colors.HexColor("#c8d9e4")),
    ]))
    story.extend([table, Paragraph("Current asset posture", st["SHsection"])])
    asset_rows = [["Asset", "Module", "Score", "Assessed"]]
    for asset in payload["assets"][:25]:
        asset_rows.append([asset["name"][:35], asset.get("module") or "-", str(asset.get("score") if asset.get("score") is not None else "-"),
                           (asset.get("last_assessed") or "-")[:10]])
    _append_table(story, asset_rows, st, [190, 145, 55, 130])
    story.append(Paragraph("Prioritized observations", st["SHsection"]))
    findings = payload["findings"][:25]
    if findings:
        for f in findings:
            story.append(KeepTogether([
                Paragraph(f'<b>{escape(f["severity"].upper())}</b> · {escape(f["title"])}', st["SHsmall"]),
                Paragraph("Asset: " + escape(f["asset_name"]) + ((" · ATT&amp;CK context: " + escape(f["attack"])) if f.get("attack") else ""), st["SHsmall"]),
                Paragraph("Action: " + escape(f["recommendation"]), st["SHsmall"]),
                Spacer(1, 5),
            ]))
    else:
        story.append(Paragraph("No current observations in the selected latest assessments.", st["SHsmall"]))
    story.append(Paragraph("Scope & limitations", st["SHsection"]))
    story.append(Paragraph("This report summarizes local workspace data, including synthetic demo entries when present. "
                           "Network checks are limited to public-domain DNS and HTTPS posture. Configuration checks "
                           "and ATT&amp;CK references are analyst context, not evidence of compromise. "
                           "are static heuristics. Device and event results rely on uploaded self-reports. "
                           "A posture score is not proof of security or regulatory compliance.", st["SHsmall"]))
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out.getvalue()


def _append_table(story, rows, st, widths):
    formatted = [[Paragraph(escape(str(cell)), st["SHcell"]) for cell in row] for row in rows]
    t = Table(formatted, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e5f0f4")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafb")]),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("LINEBELOW", (0,-1), (-1,-1), 0.6, colors.HexColor("#e0e9ef")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]))
    story.append(t)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(46, 24, "SignalHarbor | Local-first security observability")
    canvas.drawRightString(566, 24, f"Page {doc.page}")
    canvas.restoreState()
