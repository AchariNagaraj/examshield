
"""
Module 6 — Verification & Reporting
Owner: Elisha

Generates a human-readable integrity report and a professional PDF.
"""

from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)


def generate_integrity_report(
    verification_result: dict,
    center_id: str
) -> str:
    """Generate a human-readable integrity report."""

    signature_status = (
        "PASS" if verification_result.get("signature_valid", False)
        else "FAIL"
    )
    merkle_status = (
        "PASS" if verification_result.get("merkle_valid", False)
        else "FAIL"
    )
    audit_status = (
        "PASS" if verification_result.get("audit_valid", False)
        else "FAIL"
    )
    overall_status = (
        "PASS" if verification_result.get("overall", False)
        else "FAIL"
    )

    exam_on_hold = verification_result.get("exam_on_hold", False)
    generated_at = datetime.now().astimezone().strftime(
        "%d %b %Y, %I:%M:%S %p %Z"
    )

    if exam_on_hold:
        overall_status = "ON HOLD"

    report = f"""
EXAMSHIELD INTEGRITY REPORT

Exam Center: {center_id}
Generated At: {generated_at}

Paper Signature Verification : {signature_status}
Answer Merkle Root            : {merkle_status}
Audit Log Verification        : {audit_status}
Overall Integrity Status      : {overall_status}

{"WARNING: The examination is on hold. Review the incident before proceeding." if exam_on_hold else ""}
{"WARNING: Integrity verification failed. Investigate the failed checks." if overall_status == "FAIL" else ""}

This report summarizes the post-exam integrity
verification performed by ExamShield.
"""
    return report.strip()


def export_report_pdf(
    report_text: str,
    output_path: str
) -> None:
    """Export a professional, formatted integrity report as a PDF."""

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=22 * mm,
        leftMargin=22 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title="ExamShield Integrity Report",
        author="ExamShield",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ExamShieldTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=25,
        textColor=colors.HexColor("#123047"),
        alignment=TA_CENTER,
        spaceAfter=5 * mm,
    )

    subtitle_style = ParagraphStyle(
        "ExamShieldSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#607487"),
        alignment=TA_CENTER,
        spaceAfter=5 * mm,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#123047"),
        spaceBefore=5 * mm,
        spaceAfter=3 * mm,
    )

    normal_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=15,
        textColor=colors.HexColor("#334155"),
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#607487"),
    )

    # Read report fields from the text generated above.
    fields = {}
    for line in report_text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()

    center_id = fields.get("Exam Center", "Not specified")
    generated_at = fields.get("Generated At", "Not specified")
    signature = fields.get("Paper Signature Verification", "FAIL")
    merkle = fields.get("Answer Merkle Root", "FAIL")
    audit = fields.get("Audit Log Verification", "FAIL")
    overall = fields.get("Overall Integrity Status", "FAIL")

    story = []

    story.append(Paragraph("EXAMSHIELD", title_style))
    story.append(Paragraph("SECURE EXAMINATION SYSTEM", subtitle_style))
    story.append(HRFlowable(
        width="100%",
        thickness=1.5,
        color=colors.HexColor("#16866B"),
        spaceAfter=6 * mm,
    ))
    story.append(Paragraph("INTEGRITY VERIFICATION REPORT", heading_style))
    story.append(Spacer(1, 2 * mm))

    details = [
        ["Exam Center", center_id],
        ["Report Generated", generated_at],
    ]

    details_table = Table(details, colWidths=[42 * mm, 105 * mm])
    details_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EFF4F7")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#243746")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D8E2E9")),
    ]))

    story.append(details_table)
    story.append(Paragraph("Verification Checks", heading_style))

    checks = [
        ["CHECK", "RESULT"],
        ["Paper Signature Verification", signature],
        ["Answer Merkle Root", merkle],
        ["Audit Log Verification", audit],
    ]

    checks_table = Table(checks, colWidths=[105 * mm, 42 * mm], repeatRows=1)
    check_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123047")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D8E2E9")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]

    for row_index, status in enumerate([signature, merkle, audit], start=1):
        if status == "PASS":
            bg = colors.HexColor("#E5F5EC")
            fg = colors.HexColor("#17663A")
        else:
            bg = colors.HexColor("#FCE8E8")
            fg = colors.HexColor("#A61B1B")

        check_styles.extend([
            ("BACKGROUND", (1, row_index), (1, row_index), bg),
            ("TEXTCOLOR", (1, row_index), (1, row_index), fg),
            ("FONTNAME", (1, row_index), (1, row_index), "Helvetica-Bold"),
        ])

    checks_table.setStyle(TableStyle(check_styles))
    story.append(checks_table)

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("OVERALL INTEGRITY STATUS", heading_style))

    if overall == "PASS":
        status_bg = colors.HexColor("#E5F5EC")
        status_fg = colors.HexColor("#17663A")
    elif overall == "ON HOLD":
        status_bg = colors.HexColor("#FFF3D6")
        status_fg = colors.HexColor("#875900")
    else:
        status_bg = colors.HexColor("#FCE8E8")
        status_fg = colors.HexColor("#A61B1B")

    status_table = Table(
        [[Paragraph(
            f"<b>{overall}</b>",
            ParagraphStyle(
                "OverallStatus",
                parent=normal_style,
                fontSize=16,
                leading=21,
                textColor=status_fg,
                alignment=TA_CENTER,
            ),
        )]],
        colWidths=[147 * mm],
    )
    status_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), status_bg),
        ("BOX", (0, 0), (-1, -1), 0.8, status_fg),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(status_table)

    if overall == "FAIL":
        warning = (
            "<b>Warning:</b> One or more integrity checks failed. "
            "Investigate the results before accepting the examination data."
        )
        story.append(Spacer(1, 5 * mm))
        story.append(Paragraph(warning, normal_style))
    elif overall == "ON HOLD":
        story.append(Spacer(1, 5 * mm))
        story.append(Paragraph(
            "<b>Warning:</b> The examination is on hold. "
            "Review and resolve the incident through the authorized workflow.",
            normal_style,
        ))

    story.append(Spacer(1, 12 * mm))
    story.append(HRFlowable(
        width="100%",
        thickness=0.5,
        color=colors.HexColor("#D8E2E9"),
        spaceAfter=3 * mm,
    ))
    story.append(Paragraph(
        "This report summarizes the post-exam integrity verification "
        "performed by ExamShield. It reflects the verification result "
        "provided at the time of report generation.",
        small_style,
    ))

    def add_footer(canvas_obj, document):
        canvas_obj.saveState()
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(colors.HexColor("#607487"))
        canvas_obj.drawString(
            22 * mm, 12 * mm, "ExamShield | Integrity & Audit"
        )
        canvas_obj.drawRightString(
            A4[0] - 22 * mm, 12 * mm, f"Page {document.page}"
        )
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
