from __future__ import annotations

import csv
import html
import io
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from app import __version__
from app.models.db_models import Scan
from app.risk_engine.engine import severity_sort_key
from app.services.remediation_service import RemediationService
from app.services.serializers import scan_detail, vulnerability_summary


class ReportService:
    def __init__(self, remediation: RemediationService | None = None) -> None:
        self.remediation = remediation or RemediationService()

    def context(self, scan: Scan) -> dict:
        vulnerabilities = sorted(
            [vuln for vuln in scan.vulnerabilities if not vuln.withdrawn],
            key=lambda vuln: (severity_sort_key(vuln.severity), -(vuln.cvss_score or 0), vuln.osv_id),
        )
        unverified = [
            dep
            for dep in scan.dependencies
            if dep.inspection_status not in {"CHECKED", "VULNERABLE"}
        ]
        remediation = self.remediation.build(scan)
        return {
            "report_version": __version__,
            "generated_at": _iso(scan.completed_at or scan.created_at),
            "scan": scan_detail(scan),
            "vulnerabilities": [vulnerability_summary(vuln) for vuln in vulnerabilities],
            "components": [
                {
                    "id": dep.id,
                    "name": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "purl": dep.purl,
                    "direct": dep.direct,
                    "scope": dep.scope,
                    "license": dep.license,
                    "latest_version": dep.latest_version,
                    "outdated": dep.outdated,
                    "deprecated": dep.deprecated,
                    "vulnerability_count": dep.vulnerability_count,
                    "max_severity": dep.max_severity,
                    "priority_level": dep.priority_level,
                    "inspection_status": dep.inspection_status,
                    "inspection_message": dep.inspection_message,
                    "risk_reasons": dep.risk_reasons or [],
                    "source_files": dep.source_files or [],
                }
                for dep in scan.dependencies
            ],
            "remediation": remediation,
            "unverified_components": [
                {
                    "name": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "status": dep.inspection_status,
                    "message": dep.inspection_message,
                }
                for dep in unverified
            ],
            "errors": {
                "scan_errors": scan.errors or [],
                "warnings": scan.warnings or [],
                "unverified_count": len(unverified),
            },
            "sources": {
                "sources_used": scan.sources_used or [],
                "primary_vulnerability_source": "OSV.dev (https://osv.dev)",
                "optional_source": "NVD CVE API (CVSS enrichment)",
                "registry_sources": [
                    "PyPI JSON API",
                    "npm registry",
                    "Maven Central",
                    "crates.io API",
                ],
            },
            "limitations": [
                "Only versions fixed in supported dependency and lock files can be matched exactly.",
                "Vulnerability coverage depends on upstream OSV.dev data availability.",
                "Transitive dependency relationships are inferred only where lock files expose them.",
                "License and latest-version data are reported only when registry metadata is available.",
                "This report is not a substitute for a full application security assessment.",
            ],
        }

    def to_json(self, scan: Scan) -> bytes:
        return json.dumps(self.context(scan), indent=2, ensure_ascii=False).encode("utf-8")

    def to_csv(self, scan: Scan) -> bytes:
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(
            [
                "project",
                "scan_id",
                "scan_date",
                "ecosystem",
                "package",
                "version",
                "direct",
                "license",
                "latest_version",
                "outdated",
                "inspection_status",
                "priority",
                "max_severity",
                "osv_id",
                "cve_ids",
                "vulnerability_severity",
                "cvss_score",
                "patched_versions",
                "summary",
                "risk_reasons",
            ]
        )
        created = _iso(scan.completed_at or scan.created_at)
        for dep in sorted(scan.dependencies, key=lambda item: (item.ecosystem, item.name.lower())):
            vulns = [vuln for vuln in dep.vulnerabilities if not vuln.withdrawn]
            if not vulns:
                writer.writerow(
                    [
                        _csv_cell(scan.project_name),
                        _csv_cell(scan.id),
                        _csv_cell(created),
                        _csv_cell(dep.ecosystem),
                        _csv_cell(dep.name),
                        _csv_cell(dep.version),
                        "yes" if dep.direct else "no",
                        _csv_cell(dep.license),
                        _csv_cell(dep.latest_version),
                        "yes" if dep.outdated else "no",
                        _csv_cell(dep.inspection_status),
                        _csv_cell(dep.priority_level),
                        _csv_cell(dep.max_severity),
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        _csv_cell("; ".join(dep.risk_reasons or [])),
                    ]
                )
            for vuln in sorted(vulns, key=lambda item: severity_sort_key(item.severity)):
                writer.writerow(
                    [
                        _csv_cell(scan.project_name),
                        _csv_cell(scan.id),
                        _csv_cell(created),
                        _csv_cell(dep.ecosystem),
                        _csv_cell(dep.name),
                        _csv_cell(dep.version),
                        "yes" if dep.direct else "no",
                        _csv_cell(dep.license),
                        _csv_cell(dep.latest_version),
                        "yes" if dep.outdated else "no",
                        _csv_cell(dep.inspection_status),
                        _csv_cell(vuln.priority_level),
                        _csv_cell(vuln.severity),
                        _csv_cell(vuln.osv_id),
                        _csv_cell(", ".join(vuln.cve_ids or [])),
                        _csv_cell(vuln.severity),
                        _csv_cell(vuln.cvss_score if vuln.cvss_score is not None else ""),
                        _csv_cell(", ".join(vuln.fixed_versions or [])),
                        _csv_cell(_single_line(vuln.summary)),
                        _csv_cell("; ".join(vuln.priority_reasons or [])),
                    ]
                )
        return output.getvalue().encode("utf-8-sig")

    def to_html(self, scan: Scan) -> bytes:
        data = self.context(scan)
        scan_info = data["scan"]
        summary = scan_info
        severity_rows = "".join(
            f"<div class='sevrow'><span>{label}</span><div class='bar'><i style='width:{_pct(summary.get(f'{label.lower()}_count', 0), summary['vulnerability_count'])}%;background:{color}'></i></div><b>{summary.get(f'{label.lower()}_count', 0)}</b></div>"
            for label, color in (
                ("CRITICAL", "#ef4444"),
                ("HIGH", "#f97316"),
                ("MEDIUM", "#eab308"),
                ("LOW", "#38bdf8"),
                ("INFO", "#64748b"),
            )
        )
        component_rows = "".join(
            f"<tr><td>{_e(comp['name'])}</td><td>{_e(comp['version'] or '—')}</td><td>{_e(comp['ecosystem'])}</td>"
            f"<td>{'Direct' if comp['direct'] else 'Transitive'}</td><td>{_e(comp['license'] or '—')}</td>"
            f"<td>{_e(comp['latest_version'] or '—')}</td><td>{_badge(comp['max_severity'])}</td>"
            f"<td>{_e(comp['inspection_status'])}</td></tr>"
            for comp in data["components"]
        )
        vulnerability_sections = "".join(
            _html_vulnerability(vuln) for vuln in data["vulnerabilities"]
        ) or "<p class='muted'>No known vulnerabilities were reported.</p>"
        recommendations = "".join(
            f"<tr><td>{_e(rec['package'])}</td><td>{_e(rec['current_version'] or '—')}</td>"
            f"<td>{_e(rec['recommended_version'] or 'No fix published')}</td><td>{_badge(rec['priority_level'])}</td>"
            f"<td>{_e(rec['breaking_risk'])}</td><td>{_e('; '.join(rec['conflicts']))}</td></tr>"
            for rec in data["remediation"]["recommendations"]
        ) or "<tr><td colspan='6' class='muted'>No remediation actions required.</td></tr>"
        unverified = "".join(
            f"<tr><td>{_e(item['name'])}</td><td>{_e(item['version'] or '—')}</td><td>{_e(item['ecosystem'])}</td>"
            f"<td>{_e(item['status'])}</td><td>{_e(item['message'])}</td></tr>"
            for item in data["unverified_components"]
        ) or "<tr><td colspan='5' class='muted'>Every component was checked.</td></tr>"
        errors = "".join(f"<li>{_e(item)}</li>" for item in data["errors"]["scan_errors"]) or "<li class='muted'>None</li>"
        warnings = "".join(f"<li>{_e(item)}</li>" for item in data["errors"]["warnings"][:100]) or "<li class='muted'>None</li>"
        sources = "".join(f"<li>{_e(item)}</li>" for item in data["sources"]["sources_used"]) or "<li class='muted'>None recorded</li>"
        limitations = "".join(f"<li>{_e(item)}</li>" for item in data["limitations"])
        score_value = summary["security_score"]
        score_display = f"{score_value:.1f}" if score_value is not None else "N/A"
        grade = summary["score_grade"] or "N/A"
        html_output = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Dependency Watcher Report — {_e(scan.project_name)}</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#090d14;color:#dbe4f0;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
.wrap{{max-width:1200px;margin:0 auto;padding:40px 28px 80px}}h1{{font-size:30px;margin:0 0 6px}}h2{{font-size:20px;margin:38px 0 14px;border-bottom:1px solid #1e293b;padding-bottom:8px}}
.muted{{color:#7c8aa0}}.sub{{color:#8fa4be;margin:0 0 28px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px}}
.card{{background:#0f1621;border:1px solid #1e293b;border-radius:10px;padding:16px}}.card .label{{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#7c8aa0}}
.card .value{{font-size:26px;font-weight:700;margin-top:4px}}.score{{color:#60a5fa}}.critical{{color:#ef4444}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;background:#0f1621;border:1px solid #1e293b;border-radius:8px;overflow:hidden}}
th,td{{padding:9px 11px;text-align:left;border-bottom:1px solid #182131;vertical-align:top}}th{{background:#111a27;color:#93a4bb;font-size:11px;letter-spacing:.05em;text-transform:uppercase}}
.badge{{display:inline-block;padding:2px 8px;border-radius:99px;font-size:10px;font-weight:700;letter-spacing:.04em;background:#1e293b;color:#cbd5e1}}
.badge.CRITICAL{{background:#450a0a;color:#fca5a5}}.badge.HIGH{{background:#431407;color:#fdba74}}.badge.MEDIUM{{background:#422006;color:#fde047}}.badge.LOW{{background:#082f49;color:#7dd3fc}}.badge.INFO,.badge.NONE{{background:#172033;color:#94a3b8}}
.sevrow{{display:grid;grid-template-columns:90px 1fr 30px;align-items:center;gap:10px;margin:7px 0;font-size:12px}}.bar{{height:7px;background:#182131;border-radius:10px;overflow:hidden}}.bar i{{display:block;height:100%}}
.vuln{{background:#0f1621;border:1px solid #1e293b;border-left:3px solid #334155;border-radius:8px;padding:16px;margin:12px 0}}.vuln.CRITICAL{{border-left-color:#ef4444}}.vuln.HIGH{{border-left-color:#f97316}}.vuln.MEDIUM{{border-left-color:#eab308}}.vuln.LOW{{border-left-color:#38bdf8}}
.vuln h3{{margin:0 0 4px;font-size:15px}}.meta{{color:#7c8aa0;font-size:12px}}.pre{{white-space:pre-wrap}}.refs a{{color:#60a5fa;word-break:break-all}}ul{{padding-left:20px}}li{{margin:4px 0}}
footer{{margin-top:50px;color:#64748b;font-size:12px;border-top:1px solid #1e293b;padding-top:16px}}
@media print{{body{{background:#fff;color:#111}}.card,table,.vuln{{background:#fff;border-color:#ddd}}th{{background:#f3f4f6;color:#333}}}}
</style>
</head>
<body><div class="wrap">
<h1>Dependency Watcher Security Report</h1>
<p class="sub">{_e(scan_info['project_name'])} · scan <code>{_e(scan_info['id'])}</code> · {_e(data['generated_at'])}</p>
<div class="grid">
<div class="card"><div class="label">Security Score</div><div class="value score">{score_display} <small>/{grade}</small></div></div>
<div class="card"><div class="label">Dependencies</div><div class="value">{scan_info['total_dependencies']}</div></div>
<div class="card"><div class="label">Vulnerabilities</div><div class="value critical">{scan_info['vulnerability_count']}</div></div>
<div class="card"><div class="label">Critical / High</div><div class="value">{scan_info['critical_count']} / {scan_info['high_count']}</div></div>
<div class="card"><div class="label">Checked</div><div class="value">{scan_info['coverage_percent']:.1f}%</div></div>
<div class="card"><div class="label">Outdated</div><div class="value">{scan_info['outdated_count']}</div></div>
</div>
<h2>Severity distribution</h2><div class="card">{severity_rows}</div>
<h2>Executive summary</h2>
<p>Project <b>{_e(scan_info['project_name'])}</b> was scanned on {_e(data['generated_at'])} using OSV.dev advisories and package registry metadata.
The scan discovered <b>{scan_info['total_dependencies']}</b> components across {_e(', '.join(scan_info['ecosystems']) or 'no recognized ecosystem')}.
<b>{scan_info['checked_dependencies']}</b> components were checked against vulnerability data and <b>{scan_info['unknown_dependencies']}</b> remain unverified.
<b>{scan_info['vulnerability_count']}</b> vulnerability findings affect <b>{scan_info['vulnerable_dependencies']}</b> components.</p>
<h2>Vulnerabilities</h2>{vulnerability_sections}
<h2>Recommended changes</h2>
<table><thead><tr><th>Package</th><th>Current</th><th>Recommended</th><th>Priority</th><th>Breaking risk</th><th>Conflicts / notes</th></tr></thead><tbody>{recommendations}</tbody></table>
<p class="muted">{_e(data['remediation']['notice'])}</p>
<h2>Components</h2>
<table><thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Type</th><th>License</th><th>Latest</th><th>Max severity</th><th>Inspection</th></tr></thead><tbody>{component_rows}</tbody></table>
<h2>Unverified components</h2>
<table><thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Status</th><th>Reason</th></tr></thead><tbody>{unverified}</tbody></table>
<h2>Sources</h2><ul>{sources}</ul>
<h2>Errors and warnings</h2><h3>Errors</h3><ul>{errors}</ul><h3>Warnings</h3><ul>{warnings}</ul>
<h2>Limitations</h2><ul>{limitations}</ul>
<footer>Generated by Dependency Watcher v{__version__}. Vulnerability data provided by OSV.dev and its upstream sources. Dependency Watcher priority scores are proprietary heuristics and are not CVSS scores.</footer>
</div></body></html>"""
        return html_output.encode("utf-8")

    def to_pdf(self, scan: Scan) -> bytes:
        from app.reporting.pdf_renderer import render_pdf

        return render_pdf(scan, self.context(scan))


def _html_vulnerability(vuln: dict) -> str:
    refs = "".join(
        f"<a href='{_e(_safe_url(ref.get('url', '')))}' rel='noreferrer noopener'>{_e(ref.get('url', 'reference'))}</a>"
        for ref in vuln.get("references", [])
        if _safe_url(ref.get("url", ""))
    )
    fixed = ", ".join(vuln.get("fixed_versions") or []) or "No fixed version listed"
    affected = ", ".join(vuln.get("affected_versions") or []) or "Not specified"
    cve = ", ".join(vuln.get("cve_ids") or []) or vuln["osv_id"]
    score = f"{vuln['cvss_score']:.1f}" if vuln.get("cvss_score") is not None else "N/A"
    return f"""<div class="vuln {_e(vuln['severity'])}">
<h3>{_e(cve)} · {_e(vuln['osv_id'])} {_badge(vuln['severity'])}</h3>
<p>{_e(vuln.get('summary') or 'No summary provided')}</p>
<p class="pre">{_e((vuln.get('details') or '')[:4000])}</p>
<div class="meta"><b>CVSS:</b> {score} · <b>DW priority:</b> {_e(vuln['priority_level'])} ({vuln['priority_score']:.1f}/100) · <b>Published:</b> {_e(vuln.get('published') or 'unknown')}</div>
<div class="meta"><b>Affected:</b> {_e(affected)}</div>
<div class="meta"><b>Patched:</b> {_e(fixed)}</div>
<div class="meta"><b>Component:</b> {_e(vuln.get('dependency_name') or '')} {_e(vuln.get('dependency_version') or '')} ({_e(vuln.get('dependency_ecosystem') or '')})</div>
<p class="refs">{refs}</p>
</div>"""


def _badge(value: str | None) -> str:
    value = (value or "UNKNOWN").upper()
    return f"<span class='badge {_e(value)}'>{_e(value)}</span>"


def _e(value) -> str:  # noqa: ANN001
    return html.escape(str(value if value is not None else ""))


def _safe_url(value: str) -> str:
    try:
        parsed = urlparse(value)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"}:
        return ""
    return value


def _single_line(value: str | None) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _csv_cell(value) -> str:  # noqa: ANN001
    text = "" if value is None else str(value)
    if text and text[0] in {"=", "+", "-", "@", "\t", "\r", "\n"}:
        return "'" + text
    return text


def _pct(value: int, total: int) -> int:
    if not total:
        return 0
    return max(0, min(100, round(value / total * 100)))


def _iso(value) -> str | None:  # noqa: ANN001
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")
