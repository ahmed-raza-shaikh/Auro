"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        Auro — Automated Cloud Compliance Engine                            ║
║        Module: pdf_generator.py                                            ║
║        Purpose: Generate a professional PDF compliance report using        ║
║                 ReportLab. Output is written to Lambda's /tmp filesystem.  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import List, Tuple

from reportlab.lib              import colors
from reportlab.lib.enums        import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes    import A4, letter
from reportlab.lib.styles       import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units        import cm, mm
from reportlab.platypus         import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import BalancedColumns

# Local import — works inside Lambda deployment package
from cis_checks import CheckFinding, CheckStatus

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ──────────────────────────────────────────────────────────────────────────────
# Brand Colour Palette (Auro)
# ──────────────────────────────────────────────────────────────────────────────
class Palette:
    DARK_BG     = colors.HexColor("#0D1117")   # GitHub dark — header background
    ACCENT_BLUE = colors.HexColor("#1F6FEB")   # Primary accent
    ACCENT_CYAN = colors.HexColor("#39D353")   # PASS green
    FAIL_RED    = colors.HexColor("#DA3633")   # FAIL red
    WARN_AMBER  = colors.HexColor("#D29922")   # WARNING amber
    ERROR_GRAY  = colors.HexColor("#8B949E")   # ERROR / neutral
    CRIT_PURPLE = colors.HexColor("#BC8CFF")   # CRITICAL severity badge
    ROW_EVEN    = colors.HexColor("#161B22")   # Table row alternate (dark)
    ROW_ODD     = colors.HexColor("#0D1117")   # Table row alternate (darker)
    BORDER      = colors.HexColor("#30363D")   # Table border
    TEXT_LIGHT  = colors.HexColor("#E6EDF3")   # Primary text on dark
    TEXT_MUTED  = colors.HexColor("#8B949E")   # Secondary / metadata text
    WHITE       = colors.white


# ──────────────────────────────────────────────────────────────────────────────
# Status → colour mapping
# ──────────────────────────────────────────────────────────────────────────────
STATUS_COLORS = {
    CheckStatus.PASS:    Palette.ACCENT_CYAN,
    CheckStatus.FAIL:    Palette.FAIL_RED,
    CheckStatus.ERROR:   Palette.ERROR_GRAY,
    CheckStatus.WARNING: Palette.WARN_AMBER,
}

SEVERITY_COLORS = {
    "CRITICAL": Palette.CRIT_PURPLE,
    "HIGH":     Palette.FAIL_RED,
    "MEDIUM":   Palette.WARN_AMBER,
    "LOW":      Palette.ACCENT_CYAN,
}


# ──────────────────────────────────────────────────────────────────────────────
# Style Sheet Factory
# ──────────────────────────────────────────────────────────────────────────────
def _build_styles() -> dict:
    """Build and return a dictionary of named ParagraphStyles."""
    base = getSampleStyleSheet()

    custom = {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=Palette.TEXT_LIGHT,
            alignment=TA_CENTER,
            spaceAfter=6,
        ),
        "cover_subtitle": ParagraphStyle(
            "cover_subtitle",
            fontName="Helvetica",
            fontSize=13,
            leading=18,
            textColor=Palette.TEXT_MUTED,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta",
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=Palette.TEXT_MUTED,
            alignment=TA_CENTER,
        ),
        "section_heading": ParagraphStyle(
            "section_heading",
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=20,
            textColor=Palette.ACCENT_BLUE,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "check_title": ParagraphStyle(
            "check_title",
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=Palette.TEXT_LIGHT,
            spaceBefore=10,
            spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=Palette.TEXT_LIGHT,
            spaceAfter=4,
        ),
        "detail_text": ParagraphStyle(
            "detail_text",
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=Palette.TEXT_MUTED,
            spaceAfter=3,
            leftIndent=10,
        ),
        "badge_text": ParagraphStyle(
            "badge_text",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            textColor=Palette.WHITE,
            alignment=TA_CENTER,
        ),
        "footer_text": ParagraphStyle(
            "footer_text",
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=Palette.TEXT_MUTED,
            alignment=TA_CENTER,
        ),
        "toc_item": ParagraphStyle(
            "toc_item",
            fontName="Helvetica",
            fontSize=10,
            leading=16,
            textColor=Palette.TEXT_LIGHT,
        ),
        "stat_number": ParagraphStyle(
            "stat_number",
            fontName="Helvetica-Bold",
            fontSize=32,
            leading=36,
            alignment=TA_CENTER,
        ),
        "stat_label": ParagraphStyle(
            "stat_label",
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=Palette.TEXT_MUTED,
            alignment=TA_CENTER,
        ),
    }
    return custom


# ──────────────────────────────────────────────────────────────────────────────
# Page Template (dark background + header/footer)
# ──────────────────────────────────────────────────────────────────────────────

class DarkPageTemplate(PageTemplate):
    """
    Custom page template that paints a dark background and draws a consistent
    header bar + page-number footer on every page.
    """

    def __init__(self, doc, account_id: str, report_date: str):
        self.account_id  = account_id
        self.report_date = report_date

        margin = 2 * cm
        frame  = Frame(
            margin, margin,
            doc.width, doc.height,
            leftPadding=0, rightPadding=0,
            topPadding=0,  bottomPadding=0,
        )
        super().__init__("dark", frames=[frame])

    def beforeDrawPage(self, canvas, doc):
        """Paint background and draw decorative header stripe."""
        canvas.saveState()

        # ── Full-page dark background ─────────────────────────────────────────
        canvas.setFillColor(Palette.DARK_BG)
        canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)

        # ── Top accent bar ────────────────────────────────────────────────────
        canvas.setFillColor(Palette.ACCENT_BLUE)
        canvas.rect(0, doc.pagesize[1] - 8 * mm, doc.pagesize[0], 8 * mm, fill=1, stroke=0)

        # ── Header text ───────────────────────────────────────────────────────
        canvas.setFillColor(Palette.WHITE)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(
            2 * cm,
            doc.pagesize[1] - 5.5 * mm,
            "AURO  |  Automated Cloud Compliance Engine  |  CONFIDENTIAL",
        )
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            doc.pagesize[0] - 2 * cm,
            doc.pagesize[1] - 5.5 * mm,
            f"Account: {self.account_id}  |  {self.report_date}",
        )

        # ── Footer ────────────────────────────────────────────────────────────
        canvas.setFillColor(Palette.TEXT_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawCentredString(
            doc.pagesize[0] / 2,
            1.2 * cm,
            f"Page {doc.page}  |  CIS Benchmark v1.4  |  "
            "Generated by Auro Compliance Engine",
        )

        # ── Bottom rule ───────────────────────────────────────────────────────
        canvas.setStrokeColor(Palette.BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(2 * cm, 1.8 * cm, doc.pagesize[0] - 2 * cm, 1.8 * cm)

        canvas.restoreState()


# ──────────────────────────────────────────────────────────────────────────────
# Helper: coloured status badge (rendered as a small Table)
# ──────────────────────────────────────────────────────────────────────────────

def _status_badge(status: CheckStatus, styles: dict) -> Table:
    """Return a small coloured badge Table cell for a given check status."""
    colour = STATUS_COLORS.get(status, Palette.ERROR_GRAY)
    label  = Paragraph(status.value, styles["badge_text"])
    tbl    = Table([[label]], colWidths=[1.8 * cm], rowHeights=[0.55 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colour),
        ("ROUNDEDCORNERS", [4]),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    return tbl


def _severity_badge(severity: str, styles: dict) -> Table:
    """Return a small coloured severity badge."""
    colour = SEVERITY_COLORS.get(severity.upper(), Palette.ERROR_GRAY)
    label  = Paragraph(severity.upper(), styles["badge_text"])
    tbl    = Table([[label]], colWidths=[1.8 * cm], rowHeights=[0.55 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colour),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    return tbl


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(
    findings:   List[CheckFinding],
    account_id: str,
    region:     str,
    output_dir: str = "/tmp",
) -> str:
    """
    Generate a professional PDF compliance report and save it to output_dir.

    Args:
        findings:   List of CheckFinding objects from cis_checks.run_all_checks().
        account_id: AWS Account ID (embedded in report header).
        region:     AWS region the checks were run against.
        output_dir: Directory to write the PDF. Defaults to Lambda's /tmp.

    Returns:
        str: Absolute path to the generated PDF file.
    """
    now_utc     = datetime.now(timezone.utc)
    date_str    = now_utc.strftime("%Y-%m-%d")
    datetime_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    filename    = f"compliance_report_{account_id}_{date_str}.pdf"
    output_path = os.path.join(output_dir, filename)

    logger.info("Generating PDF report → %s", output_path)

    # ── Document setup ────────────────────────────────────────────────────────
    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm + 8 * mm,   # Leave room for header bar
        bottomMargin=2.5 * cm,
    )
    page_tmpl = DarkPageTemplate(doc, account_id, date_str)
    doc.addPageTemplates([page_tmpl])

    styles  = _build_styles()
    story   = []

    # ── Compute summary statistics ────────────────────────────────────────────
    total_checks = len(findings)
    pass_count   = sum(1 for f in findings if f.status == CheckStatus.PASS)
    fail_count   = sum(1 for f in findings if f.status == CheckStatus.FAIL)
    error_count  = sum(1 for f in findings if f.status == CheckStatus.ERROR)
    compliance_pct = (
        int((pass_count / total_checks) * 100) if total_checks else 0
    )

    # ══════════════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 3.5 * cm))

    story.append(Paragraph("☁", ParagraphStyle(
        "icon", fontName="Helvetica-Bold", fontSize=48,
        textColor=Palette.ACCENT_BLUE, alignment=TA_CENTER, spaceAfter=8,
    )))
    story.append(Paragraph("AURO", styles["cover_title"]))
    story.append(Paragraph(
        "Automated Cloud Compliance Engine", styles["cover_subtitle"]
    ))
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(
        width="60%", thickness=1, color=Palette.ACCENT_BLUE, spaceAfter=0.5 * cm
    ))
    story.append(Paragraph(
        "CIS AWS Foundations Benchmark v1.4 — Compliance Report",
        styles["cover_subtitle"],
    ))
    story.append(Spacer(1, 1.2 * cm))

    # ── Metadata table ────────────────────────────────────────────────────────
    meta_data = [
        ["AWS Account ID", account_id],
        ["Region Evaluated", region],
        ["Report Generated", datetime_str],
        ["Framework",        "CIS AWS Foundations Benchmark v1.4"],
        ["Engine Version",   "Auro v1.0.0"],
        ["Classification",   "CONFIDENTIAL"],
    ]
    meta_tbl = Table(meta_data, colWidths=[5 * cm, 10 * cm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#161B22")),
        ("BACKGROUND",    (1, 0), (1, -1), Palette.DARK_BG),
        ("TEXTCOLOR",     (0, 0), (0, -1), Palette.TEXT_MUTED),
        ("TEXTCOLOR",     (1, 0), (1, -1), Palette.TEXT_LIGHT),
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica"),
        ("FONTNAME",      (1, 0), (1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1),
         [colors.HexColor("#161B22"), Palette.DARK_BG]),
        ("GRID",          (0, 0), (-1, -1), 0.4, Palette.BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ]))
    story.append(meta_tbl)
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("Executive Summary", styles["section_heading"]))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=Palette.BORDER, spaceAfter=0.4 * cm
    ))

    # ── Compliance score dial (rendered as a data table row) ─────────────────
    score_colour = (
        Palette.ACCENT_CYAN if compliance_pct >= 80
        else Palette.WARN_AMBER if compliance_pct >= 50
        else Palette.FAIL_RED
    )

    score_p = Paragraph(
        f'<font color="{score_colour.hexval()}">{compliance_pct}%</font>',
        styles["stat_number"],
    )

    stat_table_data = [[
        _make_stat_cell(str(pass_count),  "PASSED",   Palette.ACCENT_CYAN, styles),
        _make_stat_cell(str(fail_count),  "FAILED",   Palette.FAIL_RED,    styles),
        _make_stat_cell(str(error_count), "ERRORS",   Palette.ERROR_GRAY,  styles),
        _make_stat_cell(f"{compliance_pct}%", "COMPLIANCE", score_colour,  styles),
    ]]
    stat_tbl = Table(stat_table_data, colWidths=[4 * cm] * 4)
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#161B22")),
        ("GRID",          (0, 0), (-1, -1), 0.5, Palette.BORDER),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(stat_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # ── Summary narrative ─────────────────────────────────────────────────────
    crit_fails = [f for f in findings if f.status == CheckStatus.FAIL and f.severity == "CRITICAL"]
    narrative  = (
        f"This report summarises the results of <b>{total_checks}</b> automated "
        f"CIS Benchmark v1.4 checks executed against AWS account "
        f"<b>{account_id}</b> on <b>{datetime_str}</b>. "
        f"The overall compliance score is <b>{compliance_pct}%</b> "
        f"({pass_count} passed, {fail_count} failed, {error_count} errors). "
    )
    if crit_fails:
        narrative += (
            f"<b>{len(crit_fails)} CRITICAL finding(s)</b> require immediate attention "
            "and should be remediated before next audit cycle."
        )
    else:
        narrative += "No CRITICAL findings were identified in this assessment cycle."

    story.append(Paragraph(narrative, styles["body"]))
    story.append(Spacer(1, 0.5 * cm))

    # ── Findings summary table ────────────────────────────────────────────────
    story.append(Paragraph("Findings Overview", styles["section_heading"]))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=Palette.BORDER, spaceAfter=0.3 * cm
    ))

    summary_header = [
        Paragraph("<b>Check ID</b>",   styles["body"]),
        Paragraph("<b>Title</b>",      styles["body"]),
        Paragraph("<b>Severity</b>",   styles["body"]),
        Paragraph("<b>Status</b>",     styles["body"]),
    ]
    summary_rows = [summary_header]

    for f in findings:
        summary_rows.append([
            Paragraph(f.check_id, styles["detail_text"]),
            Paragraph(f.title,    styles["body"]),
            _severity_badge(f.severity, styles),
            _status_badge(f.status, styles),
        ])

    summary_tbl = Table(
        summary_rows,
        colWidths=[3.2 * cm, 8.5 * cm, 2.3 * cm, 2.3 * cm],
        repeatRows=1,
    )
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#1F2937")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
         [colors.HexColor("#0D1117"), colors.HexColor("#161B22")]),
        ("GRID",          (0, 0), (-1, -1), 0.4, Palette.BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_tbl)
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # DETAILED FINDINGS (one block per check)
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("Detailed Findings", styles["section_heading"]))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=Palette.BORDER, spaceAfter=0.4 * cm
    ))

    for idx, finding in enumerate(findings, start=1):
        block = _build_finding_block(idx, finding, styles)
        story.append(KeepTogether(block))
        story.append(Spacer(1, 0.4 * cm))

    # ══════════════════════════════════════════════════════════════════════════
    # REMEDIATION QUICK-REFERENCE
    # ══════════════════════════════════════════════════════════════════════════
    failed_findings = [f for f in findings if f.status == CheckStatus.FAIL]

    if failed_findings:
        story.append(PageBreak())
        story.append(Paragraph(
            "Remediation Quick Reference", styles["section_heading"]
        ))
        story.append(HRFlowable(
            width="100%", thickness=0.5, color=Palette.BORDER, spaceAfter=0.4 * cm
        ))
        story.append(Paragraph(
            "The following table consolidates recommended remediation steps for "
            "all failed checks. Prioritise CRITICAL and HIGH severity items first.",
            styles["body"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        rem_header = [
            Paragraph("<b>Check ID</b>",      styles["body"]),
            Paragraph("<b>Severity</b>",      styles["body"]),
            Paragraph("<b>Remediation</b>",   styles["body"]),
            Paragraph("<b>Affected Resources</b>", styles["body"]),
        ]
        rem_rows = [rem_header]

        REMEDIATION_MAP = {
            "CIS-1.1/1.5": (
                "Navigate to IAM → Security credentials → Activate MFA for root. "
                "Delete all root access keys. Use IAM roles for programmatic access."
            ),
            "CIS-1.8": (
                "Update IAM Account Password Policy: MinLength=14, require uppercase/"
                "lowercase/numbers/symbols, MaxAge=90, ReusePrevent=24."
            ),
            "CIS-3.1/3.2": (
                "Create a multi-region trail in CloudTrail console. Enable log file "
                "validation. Ensure management events are recorded."
            ),
            "CIS-2.1.2/2.1.5": (
                "Enable 'Block All Public Access' at both account and bucket level "
                "in S3 console. Review and remove public-granting ACLs/policies."
            ),
            "CIS-5.2/5.3": (
                "Edit security group ingress rules: replace 0.0.0.0/0 on port 22/3389 "
                "with specific IP ranges (VPN CIDR, office IP). Use AWS Systems Manager "
                "Session Manager as a bastion alternative."
            ),
        }

        for f in failed_findings:
            rem_text   = REMEDIATION_MAP.get(f.check_id, "Review AWS documentation.")
            resources  = "\n".join(f.resources[:5]) if f.resources else "N/A"
            if len(f.resources) > 5:
                resources += f"\n... +{len(f.resources) - 5} more"

            rem_rows.append([
                Paragraph(f.check_id,  styles["detail_text"]),
                _severity_badge(f.severity, styles),
                Paragraph(rem_text,    styles["body"]),
                Paragraph(resources,   styles["detail_text"]),
            ])

        rem_tbl = Table(
            rem_rows,
            colWidths=[3 * cm, 2 * cm, 7.5 * cm, 3.8 * cm],
            repeatRows=1,
        )
        rem_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#1F2937")),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1),
             [colors.HexColor("#0D1117"), colors.HexColor("#161B22")]),
            ("GRID",          (0, 0), (-1, -1), 0.4, Palette.BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        story.append(rem_tbl)

    # ── Build document ────────────────────────────────────────────────────────
    doc.build(story)
    logger.info("PDF report generated successfully: %s", output_path)
    return output_path


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_stat_cell(
    number: str, label: str, colour: colors.Color, styles: dict
) -> Table:
    """Render a single KPI stat cell (number + label stacked)."""
    num_para   = Paragraph(
        f'<font color="{colour.hexval()}"><b>{number}</b></font>',
        styles["stat_number"],
    )
    label_para = Paragraph(label, styles["stat_label"])
    inner_tbl  = Table([[num_para], [label_para]], colWidths=[4 * cm])
    inner_tbl.setStyle(TableStyle([
        ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return inner_tbl


def _build_finding_block(
    idx: int, finding: CheckFinding, styles: dict
) -> list:
    """
    Build a list of ReportLab Flowables representing one complete check finding.
    Wrapped in KeepTogether by the caller to prevent page-break mid-block.
    """
    border_colour = STATUS_COLORS.get(finding.status, Palette.ERROR_GRAY)
    flowables     = []

    # ── Title row: status badge | severity badge | check ID — title ──────────
    title_row_data = [[
        _status_badge(finding.status, styles),
        _severity_badge(finding.severity, styles),
        Paragraph(
            f"<b>{finding.check_id}</b> — {finding.title}",
            styles["check_title"],
        ),
    ]]
    title_row = Table(
        title_row_data,
        colWidths=[2.2 * cm, 2.2 * cm, 11.9 * cm],
    )
    title_row.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#161B22")),
        ("LINEABOVE",  (0, 0), (-1, 0),  1.5, border_colour),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("GRID",       (0, 0), (-1, -1), 0.4, Palette.BORDER),
    ]))
    flowables.append(title_row)

    # ── Description ──────────────────────────────────────────────────────────
    flowables.append(Paragraph(
        f"<i>{finding.description}</i>", styles["body"]
    ))

    # ── Detail text (pre-formatted) ───────────────────────────────────────────
    if finding.details:
        # Split multi-line details for better rendering
        for line in finding.details.split("\n"):
            line = line.strip()
            if line:
                flowables.append(Paragraph(line, styles["detail_text"]))

    # ── Affected resources (if any) ───────────────────────────────────────────
    if finding.resources:
        flowables.append(Paragraph(
            f"<b>Affected Resources ({len(finding.resources)}):</b>",
            styles["body"],
        ))
        for res in finding.resources[:10]:   # Cap at 10 to avoid page overflow
            flowables.append(Paragraph(f"  → {res}", styles["detail_text"]))
        if len(finding.resources) > 10:
            flowables.append(Paragraph(
                f"  ... and {len(finding.resources) - 10} more resource(s).",
                styles["detail_text"],
            ))

    return flowables
