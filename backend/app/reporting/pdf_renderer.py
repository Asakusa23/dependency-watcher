from __future__ import annotations

import io
import os
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.db_models import Scan


_FONT_REGULAR = "Helvetica"
_FONT_BOLD = "Helvetica-Bold"
_FONTS_READY = False


def render_pdf(scan: Scan, context: dict) -> bytes:
    _ensure_fonts()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Dependency Watcher Report - {scan.project_name}",
        author="Dependency Watcher",
        subject="Software supply chain security report",
    )
    styles = _styles()
    story: list = []
    info = context["scan"]
    story.append(Paragraph("Dependency Watcher", styles["Brand"]))
    story.append(Paragraph("Software Supply Chain Security Report", styles["Title"]))
    story.append(
        Paragraph(
            f"{_p(info['project_name'])} &nbsp;|&nbsp; Scan {_p(info['id'])} &nbsp;|&nbsp; {_p(context.get('generated_at') or '')}",
            styles["Muted"],
        )
    )
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=0.8, color=_BLUE, spaceBefore=0, spaceAfter=14))

    score = info["security_score"]
    score_text = f"{score:.1f} / 100 (grade {info['score_grade']})" if score is not None else "N/A"
    stats = [
        [Paragraph("<b>Security score</b>", styles["Cell"]), Paragraph("<b>Dependencies</b>", styles["Cell"]), Paragraph("<b>Vulnerabilities</b>", styles["Cell"])],
        [Paragraph(score_text, styles["CellStrong"]), Paragraph(str(info["total_dependencies"]), styles["CellStrong"]), Paragraph(str(info["vulnerability_count"]), styles["CellStrong"])],
        [Paragraph("<b>Critical / High</b>", styles["Cell"]), Paragraph("<b>Checked coverage</b>", styles["Cell"]), Paragraph("<b>Outdated</b>", styles["Cell"])],
        [
            Paragraph(f"{info['critical_count']} / {info['high_count']}", styles["CellStrong"]),
            Paragraph(f"{info['coverage_percent']:.1f}%", styles["CellStrong"]),
            Paragraph(str(info["outdated_count"]), styles["CellStrong"]),
        ],
    ]
    stats_table = Table(stats, colWidths=[60 * mm, 60 * mm, 60 * mm])
    stats_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _PANEL),
                ("BOX", (0, 0), (-1, -1), 0.6, _BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(stats_table)
    story.append(Spacer(1, 14))

    _heading(story, "Executive summary", styles)
    summary = (
        f"Project <b>{_p(info['project_name'])}</b> was scanned using OSV.dev advisories and package registry metadata. "
        f"The scan discovered <b>{info['total_dependencies']}</b> components across {_p(', '.join(info['ecosystems']) or 'no recognized ecosystem')}. "
        f"<b>{info['checked_dependencies']}</b> components were checked against vulnerability data; <b>{info['unknown_dependencies']}</b> remain unverified. "
        f"<b>{info['vulnerability_count']}</b> findings affect <b>{info['vulnerable_dependencies']}</b> components. "
        f"The proprietary security score is <b>{score_text}</b> and reflects both findings and verification coverage."
    )
    story.append(Paragraph(summary, styles["Body"]))
    if info.get("score_breakdown"):
        breakdown = info["score_breakdown"]
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                _p(
                    "Score formula: "
                    + str(breakdown.get("formula", ""))
                    + ". Vulnerability penalty: "
                    + str(breakdown.get("vulnerability_penalty", ""))
                    + "; coverage: "
                    + str(breakdown.get("coverage_percent", ""))
                    + "%. This score is not a CVSS score."
                ),
                styles["Small"],
            )
        )

    _heading(story, "Severity distribution", styles)
    severity_data = [["Severity", "Findings"]]
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity_data.append([label, str(info.get(f"{label.lower()}_count", 0))])
    story.append(_basic_table(severity_data, [70 * mm, 40 * mm], styles))

    if context["vulnerabilities"]:
        _heading(story, "Vulnerability findings", styles)
        for vuln in context["vulnerabilities"]:
            story.append(_vulnerability_block(vuln, styles))
    else:
        _heading(story, "Vulnerability findings", styles)
        story.append(Paragraph("No known vulnerabilities were reported for the inspected components.", styles["Body"]))

    _heading(story, "Recommended changes", styles)
    recommendations = context["remediation"]["recommendations"]
    if recommendations:
        rows = [["Package", "Current", "Recommended", "Priority", "Risk", "Notes"]]
        for rec in recommendations:
            rows.append(
                [
                    _p(f"{rec['package']}\n{rec['ecosystem']}"),
                    _p(rec["current_version"] or "-"),
                    _p(rec["recommended_version"] or "No fix published"),
                    _p(rec["priority_level"]),
                    _p(rec["breaking_risk"]),
                    _p("; ".join(rec["conflicts"]) or "-"),
                ]
            )
        story.append(_basic_table(rows, [52 * mm, 24 * mm, 30 * mm, 20 * mm, 16 * mm, 38 * mm], styles, font_size=7.5))
        story.append(Spacer(1, 5))
        story.append(Paragraph(_p(context["remediation"]["notice"]), styles["Small"]))
    else:
        story.append(Paragraph("No remediation actions are required based on available data.", styles["Body"]))

    _heading(story, "Components", styles)
    component_rows = [["Package", "Version", "Ecosystem", "Latest", "Severity", "Inspection"]]
    for comp in context["components"]:
        component_rows.append(
            [
                _p(comp["name"] + (" (direct)" if comp["direct"] else "")),
                _p(comp["version"] or "-"),
                _p(comp["ecosystem"]),
                _p(comp["latest_version"] or "-"),
                _p(comp["max_severity"]),
                _p(comp["inspection_status"]),
            ]
        )
    story.append(_basic_table(component_rows, [57 * mm, 27 * mm, 24 * mm, 27 * mm, 20 * mm, 25 * mm], styles, font_size=7.5))

    _heading(story, "Unverified components", styles)
    unverified = context["unverified_components"]
    if unverified:
        rows = [["Package", "Version", "Ecosystem", "Status", "Reason"]]
        for item in unverified:
            rows.append(
                [
                    _p(item["name"]),
                    _p(item["version"] or "-"),
                    _p(item["ecosystem"]),
                    _p(item["status"]),
                    _p(item["message"] or "-"),
                ]
            )
        story.append(_basic_table(rows, [45 * mm, 22 * mm, 24 * mm, 24 * mm, 55 * mm], styles, font_size=7.5))
    else:
        story.append(Paragraph("Every component was inspected.", styles["Body"]))

    _heading(story, "Sources", styles)
    for source in context["sources"]["sources_used"] or ["No source was recorded"]:
        story.append(Paragraph("• " + _p(source), styles["Body"]))

    _heading(story, "Errors and warnings", styles)
    errors = context["errors"]["scan_errors"]
    warnings = context["errors"]["warnings"][:100]
    story.append(Paragraph("<b>Errors</b>", styles["Body"]))
    for item in errors or ["None"]:
        story.append(Paragraph("• " + _p(item), styles["Small"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Warnings</b>", styles["Body"]))
    for item in warnings or ["None"]:
        story.append(Paragraph("• " + _p(item), styles["Small"]))

    _heading(story, "Limitations", styles)
    for item in context["limitations"]:
        story.append(Paragraph("• " + _p(item), styles["Small"]))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Generated by Dependency Watcher. Vulnerability data originates from OSV.dev and its upstream sources. DW priority scores are proprietary heuristics, not CVSS scores.", styles["Muted"]))
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


_BLUE = colors.HexColor("#3b82f6")
_PANEL = colors.HexColor("#f8fafc")
_BORDER = colors.HexColor("#cbd5e1")
_TEXT = colors.HexColor("#0f172a")
_MUTED = colors.HexColor("#64748b")


def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "Brand": ParagraphStyle("Brand", fontName=_FONT_BOLD, fontSize=9, textColor=_BLUE, spaceAfter=4, tracking=1),
        "Title": ParagraphStyle("DWTitle", fontName=_FONT_BOLD, fontSize=20, leading=24, textColor=_TEXT, spaceAfter=4),
        "H2": ParagraphStyle("DWH2", fontName=_FONT_BOLD, fontSize=13, leading=16, textColor=_TEXT, spaceBefore=12, spaceAfter=6),
        "Body": ParagraphStyle("DWBody", fontName=_FONT_REGULAR, fontSize=9, leading=13, textColor=_TEXT, spaceAfter=4, alignment=TA_LEFT),
        "Small": ParagraphStyle("DWSmall", fontName=_FONT_REGULAR, fontSize=7.6, leading=10.5, textColor=_MUTED, spaceAfter=2),
        "Muted": ParagraphStyle("DWMuted", fontName=_FONT_REGULAR, fontSize=8.5, leading=11, textColor=_MUTED),
        "Cell": ParagraphStyle("DWCell", fontName=_FONT_REGULAR, fontSize=8, leading=10, textColor=_MUTED),
        "CellStrong": ParagraphStyle("DWCellStrong", fontName=_FONT_BOLD, fontSize=12, leading=14, textColor=_TEXT),
        "Table": ParagraphStyle("DWTable", fontName=_FONT_REGULAR, fontSize=7.5, leading=9.5, textColor=_TEXT),
        "TableHead": ParagraphStyle("DWTableHead", fontName=_FONT_BOLD, fontSize=7.5, leading=9.5, textColor=_TEXT),
        "VulnTitle": ParagraphStyle("DWVulnTitle", fontName=_FONT_BOLD, fontSize=9.5, leading=12, textColor=_TEXT, spaceAfter=2),
        "VulnBody": ParagraphStyle("DWVulnBody", fontName=_FONT_REGULAR, fontSize=7.5, leading=10, textColor=_TEXT),
        "Link": ParagraphStyle("DWLink", fontName=_FONT_REGULAR, fontSize=7, leading=9, textColor=colors.HexColor("#1d4ed8")),
    }


def _heading(story: list, title: str, styles: dict) -> None:
    story.append(Spacer(1, 6))
    story.append(Paragraph(_p(title), styles["H2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER, spaceBefore=0, spaceAfter=6))


def _basic_table(rows: list[list[str]], widths: list[float], styles: dict, font_size: float = 8) -> LongTable:
    converted = []
    for row_index, row in enumerate(rows):
        style = styles["TableHead"] if row_index == 0 else styles["Table"]
        converted.append([Paragraph(str(cell), style) for cell in row])
    table = LongTable(converted, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _PANEL),
                ("TEXTCOLOR", (0, 0), (-1, -1), _TEXT),
                ("BOX", (0, 0), (-1, -1), 0.5, _BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _vulnerability_block(vuln: dict, styles: dict) -> Table:
    cve = ", ".join(vuln.get("cve_ids") or []) or vuln["osv_id"]
    refs = [
        ref.get("url", "")
        for ref in vuln.get("references", [])
        if _is_safe_url(ref.get("url", ""))
    ]
    ref_text = " ".join(
        f'<link href="{escape(url)}" color="blue">{escape(_shorten(url, 90))}</link>' for url in refs[:4]
    )
    details = _p((vuln.get("details") or "")[:900] + ("..." if len(vuln.get("details") or "") > 900 else ""))
    score = f"{vuln['cvss_score']:.1f}" if vuln.get("cvss_score") is not None else "N/A"
    content = (
        f"<b>{_p(cve)} · {_p(vuln['osv_id'])} · {_p(vuln['severity'])}</b><br/>"
        f"{_p(vuln.get('summary') or 'No summary provided')}<br/><br/>"
        f"{details}<br/><br/>"
        f"<b>CVSS:</b> {score} &nbsp; <b>DW priority:</b> {_p(vuln['priority_level'])} ({vuln['priority_score']:.1f}/100) &nbsp; "
        f"<b>Published:</b> {_p(vuln.get('published') or 'unknown')}<br/>"
        f"<b>Affected:</b> {_p(', '.join(vuln.get('affected_versions') or []) or 'not specified')}<br/>"
        f"<b>Patched:</b> {_p(', '.join(vuln.get('fixed_versions') or []) or 'no fixed version listed')}<br/>"
        f"<b>Component:</b> {_p(vuln.get('dependency_name') or '')} {_p(vuln.get('dependency_version') or '')} "
        f"({_p(vuln.get('dependency_ecosystem') or '')})<br/>"
        f"<font size='6.5' color='#1d4ed8'>{ref_text}</font>"
    )
    row = Table([[Paragraph(content, styles["VulnBody"])]], colWidths=[180 * mm])
    row.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fbfdff")),
                ("BOX", (0, 0), (-1, -1), 0.4, _BORDER),
                ("LINEBEFORE", (0, 0), (0, -1), 2, _severity_color(vuln.get("severity"))),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return row


def _severity_color(severity: str | None):  # noqa: ANN201
    return {
        "CRITICAL": colors.HexColor("#dc2626"),
        "HIGH": colors.HexColor("#ea580c"),
        "MEDIUM": colors.HexColor("#ca8a04"),
        "LOW": colors.HexColor("#0284c7"),
        "INFO": colors.HexColor("#64748b"),
    }.get((severity or "").upper(), colors.HexColor("#64748b"))


def _footer(canvas, doc):  # noqa: ANN001
    canvas.saveState()
    canvas.setStrokeColor(_BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(15 * mm, 12 * mm, A4[0] - 15 * mm, 12 * mm)
    canvas.setFont(_FONT_REGULAR, 7)
    canvas.setFillColor(_MUTED)
    canvas.drawString(15 * mm, 8 * mm, "Dependency Watcher · Software Supply Chain Security")
    canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _ensure_fonts() -> None:
    global _FONT_REGULAR, _FONT_BOLD, _FONTS_READY
    if _FONTS_READY:
        return
    _FONTS_READY = True
    candidates = [
        (Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "segoeui.ttf", Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "segoeuib.ttf"),
        (Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "arial.ttf", Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "arialbd.ttf"),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
        (Path("/System/Library/Fonts/Supplemental/Arial.ttf"), Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf")),
        (Path("/System/Library/Fonts/Helvetica.ttc"), Path("/System/Library/Fonts/Helvetica.ttc")),
    ]
    for regular, bold in candidates:
        try:
            if regular.exists():
                pdfmetrics.registerFont(TTFont("DWFont", str(regular)))
                _FONT_REGULAR = "DWFont"
                if bold.exists():
                    pdfmetrics.registerFont(TTFont("DWFont-Bold", str(bold)))
                    _FONT_BOLD = "DWFont-Bold"
                else:
                    _FONT_BOLD = "DWFont"
                return
        except Exception:
            continue


def _p(value) -> str:  # noqa: ANN001
    text = escape(str(value if value is not None else ""))
    return text.replace("\n", "<br/>")


def _is_safe_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"}


def _shorten(value: str, length: int) -> str:
    return value if len(value) <= length else value[: length - 3] + "..."
