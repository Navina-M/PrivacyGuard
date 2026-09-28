"""
dlp/report_pdf.py

Generates polished, executive-ready PDF audit reports using ReportLab.
Ensures zero sensitive raw data leakage by only writing masked values.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from datetime import datetime
from typing import List, Dict, Optional

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#2563eb"),
}

LEVEL_BG_COLORS = {
    "CRITICAL": colors.HexColor("#fef2f2"),
    "HIGH": colors.HexColor("#fff7ed"),
    "MEDIUM": colors.HexColor("#fffbeb"),
    "LOW": colors.HexColor("#eff6ff"),
}


def generate_report(
    output_path: str,
    filename: str,
    assessment: Dict,
    findings: List[Dict],
    explanations: Optional[List[Dict]] = None
) -> str:
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        alignment=0,
    )

    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=8,
        spaceAfter=4,
    )

    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    table_cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b"),
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )

    story = []

    # Title & Subtitle Header
    story.append(Paragraph("PrivacyGuard Edge — DLP Risk Assessment Audit", title_style))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        f"<b>Document Analyzed:</b> {filename} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Audit Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Engine:</b> PrivacyGuard Edge v2.0 (On-Device)",
        body_style
    ))
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

    # Executive Summary Card
    level = assessment.get("level", "LOW")
    level_color = SEVERITY_COLORS.get(level, colors.HexColor("#2563eb"))
    score = assessment.get("score", 0)

    summary_data = [
        [
            Paragraph(f"<font size=18 color='{level_color.hexval()}'><b>{level} RISK</b></font><br/><font color='#64748b'>Risk Score: <b>{score}</b>/999</font>", styles["Normal"]),
            Paragraph(f"<b>Key Recommendation:</b><br/>{assessment.get('recommendation', '')}", body_style),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[55 * mm, 125 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LEVEL_BG_COLORS.get(level, colors.HexColor("#f8fafc"))),
        ("BOX", (0, 0), (-1, -1), 1, level_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 4 * mm))

    # Severity Breakdown Chips Table
    counts = assessment.get("counts_by_severity", {})
    sev_summary = [
        [
            Paragraph(f"<b>Critical:</b> {counts.get('CRITICAL', 0)}", body_style),
            Paragraph(f"<b>High:</b> {counts.get('HIGH', 0)}", body_style),
            Paragraph(f"<b>Medium:</b> {counts.get('MEDIUM', 0)}", body_style),
            Paragraph(f"<b>Low:</b> {counts.get('LOW', 0)}", body_style),
            Paragraph(f"<b>Total Findings:</b> {len(findings)}", body_style),
        ]
    ]
    sev_table = Table(sev_summary, colWidths=[36 * mm] * 5)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 4 * mm))

    # Risk Reasons
    story.append(Paragraph("<b>Risk Factors Identified:</b>", h2_style))
    for reason in assessment.get("reasons", []):
        story.append(Paragraph(f"• {reason}", body_style))
    story.append(Spacer(1, 4 * mm))

    # Findings Table
    story.append(Paragraph("<b>Structured Findings Inventory:</b>", h2_style))
    table_data = [[
        Paragraph("Type", table_header_style),
        Paragraph("Category", table_header_style),
        Paragraph("Detected Value", table_header_style),
        Paragraph("Severity", table_header_style),
        Paragraph("Conf.", table_header_style),
        Paragraph("Source", table_header_style),
    ]]

    for f in findings:
        s_color = SEVERITY_COLORS.get(f.get("severity", "LOW"), colors.black).hexval()
        table_data.append([
            Paragraph(f.get("type", ""), table_cell_style),
            Paragraph(f.get("category", ""), table_cell_style),
            Paragraph(f"<code>{f.get('value', '')}</code>", table_cell_style),
            Paragraph(f"<font color='{s_color}'><b>{f.get('severity', '')}</b></font>", table_cell_style),
            Paragraph(f"{round(f.get('confidence', 0) * 100)}%", table_cell_style),
            Paragraph(f.get("source", ""), table_cell_style),
        ])

    if len(table_data) > 1:
        t = Table(table_data, colWidths=[35 * mm, 38 * mm, 45 * mm, 24 * mm, 18 * mm, 20 * mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No sensitive items detected.", body_style))

    # Explanations / Remediation
    if explanations:
        story.append(Spacer(1, 5 * mm))
        story.append(Paragraph("<b>Detailed Remediation Guidance (High / Critical Findings):</b>", h2_style))
        for ex in explanations:
            s_color = SEVERITY_COLORS.get(ex.get("severity", "LOW"), colors.black).hexval()
            story.append(Paragraph(
                f"<b><font color='{s_color}'>[{ex.get('severity')}] {ex.get('type')}</font></b> — {ex.get('reason')}<br/>"
                f"&nbsp;&nbsp;<b>Recommended Action:</b> {ex.get('recommended_action')}",
                body_style,
            ))
            story.append(Spacer(1, 2 * mm))

    doc.build(story)
    return output_path
