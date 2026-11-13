#!/usr/bin/env python3
"""Dependency Watcher command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.core.config import build_settings  # noqa: E402
from app.core.container import build_container  # noqa: E402
from app.core.security import SecurityError, validate_github_url  # noqa: E402
from app.services.serializers import scan_detail, scan_summary  # noqa: E402


def _container(args: argparse.Namespace):
    settings = build_settings(getattr(args, "data_dir", None))
    container = build_container(settings)
    if getattr(args, "no_osv", False):
        container.settings.enable_osv = False
    if getattr(args, "no_registry", False):
        container.settings.enable_registry = False
    if getattr(args, "no_github", False):
        container.settings.enable_github = False
    return container


def _write_outputs(container, scan, args: argparse.Namespace) -> list[Path]:
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    full = container.scan_service.get_scan(scan.id, full=True)
    if full is None:
        raise RuntimeError("Scan result disappeared")
    if args.report:
        for fmt in [item.strip() for item in args.report.split(",") if item.strip()]:
            if fmt not in {"json", "html", "csv", "pdf"}:
                raise SystemExit(f"Unsupported report format: {fmt}")
            content = getattr(container.report_service, f"to_{fmt}")(full)
            path = out_dir / f"report-{scan.id[:8]}.{fmt}"
            path.write_bytes(content)
            written.append(path)
    if args.sbom:
        for fmt in [item.strip() for item in args.sbom.split(",") if item.strip()]:
            if fmt == "json":
                content = container.sbom_generator.to_json(full).encode("utf-8")
                path = out_dir / f"sbom-{scan.id[:8]}.cdx.json"
            elif fmt == "xml":
                content = container.sbom_generator.to_xml(full).encode("utf-8")
                path = out_dir / f"sbom-{scan.id[:8]}.cdx.xml"
            else:
                raise SystemExit(f"Unsupported SBOM format: {fmt}")
            path.write_bytes(content)
            written.append(path)
    return written


def cmd_scan(args: argparse.Namespace) -> int:
    container = _container(args)
    raw = args.target
    if args.github or raw.startswith(("https://github.com/", "http://github.com/")):
        try:
            owner, repo, ref = validate_github_url(raw, container.settings.github_hosts)
        except SecurityError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        scan = container.scan_service.create_scan(
            source_type="github",
            project_name=args.name or repo,
            source_reference=f"https://github.com/{owner}/{repo}" + (f"/tree/{ref}" if ref else ""),
            metadata={"ref": ref or ""},
        )
    else:
        try:
            path = container.scan_service.validate_local_path(str(Path(raw).expanduser().resolve()))
        except (SecurityError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        scan = container.scan_service.create_scan(
            source_type="local",
            project_name=args.name or path.name,
            source_reference=str(path),
            metadata={"project_root": str(path)},
        )
    print(f"Scan {scan.id} started for {scan.project_name}")
    asyncio.run(container.scan_service.execute(scan.id))
    full = container.scan_service.get_scan(scan.id, full=True)
    if full is None:
        print("error: scan record disappeared", file=sys.stderr)
        return 2
    if full.status != "completed":
        print(f"error: scan failed: {full.error_message}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(scan_detail(full), indent=2))
    else:
        print(f"Status:             {full.status}")
        print(f"Dependencies:       {full.total_dependencies} ({full.direct_dependencies} direct)")
        print(f"Vulnerabilities:    {full.vulnerability_count} across {full.vulnerable_dependencies} components")
        print(f"Critical / High:    {full.critical_count} / {full.high_count}")
        print(f"Checked coverage:   {full.coverage_percent:.1f}%")
        print(f"Security score:     {full.security_score if full.security_score is not None else 'N/A'} ({full.score_grade})")
        print(f"Outdated:           {full.outdated_count}")
        print(f"Duration:           {full.duration_seconds:.2f}s")
        if full.warnings:
            print(f"Warnings:           {len(full.warnings)} (see report)")
    written = _write_outputs(container, full, args)
    for path in written:
        print(f"Wrote: {path}")
    if args.fail_on and _fails_threshold(full, args.fail_on):
        return 3
    return 0


def _fails_threshold(scan, threshold: str) -> bool:
    order = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    target = order[threshold]
    counts = {
        "critical": scan.critical_count,
        "high": scan.high_count,
        "medium": scan.medium_count,
        "low": scan.low_count,
        "info": scan.info_count,
    }
    return any(counts[level] > 0 for level, rank in order.items() if rank >= target)


def cmd_list(args: argparse.Namespace) -> int:
    container = _container(args)
    with container.database.session() as session:
        from sqlalchemy import select

        from app.models.db_models import Scan

        scans = session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(args.limit)).all()
    if not scans:
        print("No scans found.")
        return 0
    print(f"{'SCAN ID':34} {'STATUS':10} {'SCORE':6} {'DEPS':5} {'VULNS':6} PROJECT")
    for scan in scans:
        score = f"{scan.security_score:.1f}" if scan.security_score is not None else "N/A"
        print(
            f"{scan.id:34} {scan.status:10} {score:6} {scan.total_dependencies:5} "
            f"{scan.vulnerability_count:6} {scan.project_name}"
        )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    container = _container(args)
    scan = container.scan_service.get_scan(args.scan_id, full=True)
    if scan is None:
        print("error: scan not found", file=sys.stderr)
        return 2
    print(json.dumps(scan_detail(scan), indent=2))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    container = _container(args)
    scan = container.scan_service.get_scan(args.scan_id, full=True)
    if scan is None:
        print("error: scan not found", file=sys.stderr)
        return 2
    content = getattr(container.report_service, f"to_{args.format}")(scan)
    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(content)
    print(f"Wrote: {out}")
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    container = _container(args)
    scan = container.scan_service.get_scan(args.scan_id, full=True)
    if scan is None:
        print("error: scan not found", file=sys.stderr)
        return 2
    if args.format == "json":
        content = container.sbom_generator.to_json(scan).encode("utf-8")
    else:
        content = container.sbom_generator.to_xml(scan).encode("utf-8")
    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(content)
    print(f"Wrote: {out}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    container = _container(args)
    first = container.scan_service.get_scan(args.scan_a, full=True)
    second = container.scan_service.get_scan(args.scan_b, full=True)
    if first is None or second is None:
        print("error: scan not found", file=sys.stderr)
        return 2
    result = container.comparison_service.compare(first, second)
    text = json.dumps(result, indent=2)
    if args.output:
        out = Path(args.output).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"Wrote: {out}")
    else:
        print(text)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=False,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dw", description="Dependency Watcher CLI")
    parser.add_argument("--data-dir", help="Directory for database, cache and settings")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a local path or GitHub repository")
    scan.add_argument("target", help="Local directory or GitHub repository URL")
    scan.add_argument("--github", action="store_true", help="Treat target as a GitHub repository URL")
    scan.add_argument("--name", help="Project name")
    scan.add_argument("--out", default="dw-reports", help="Output directory for reports/SBOM")
    scan.add_argument("--report", help="Comma-separated report formats: json,html,csv,pdf")
    scan.add_argument("--sbom", help="Comma-separated SBOM formats: json,xml")
    scan.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])
    scan.add_argument("--no-osv", action="store_true", help="Disable OSV vulnerability checks for this run")
    scan.add_argument("--no-registry", action="store_true", help="Disable registry health checks")
    scan.add_argument("--no-github", action="store_true", help="Disable GitHub source")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)

    list_parser = sub.add_parser("list", help="List previous scans")
    list_parser.add_argument("--limit", type=int, default=20)
    list_parser.set_defaults(func=cmd_list)

    show = sub.add_parser("show", help="Show scan metadata as JSON")
    show.add_argument("scan_id")
    show.set_defaults(func=cmd_show)

    report = sub.add_parser("report", help="Generate a report")
    report.add_argument("scan_id")
    report.add_argument("--format", choices=["json", "html", "csv", "pdf"], required=True)
    report.add_argument("--output", required=True)
    report.set_defaults(func=cmd_report)

    sbom = sub.add_parser("sbom", help="Generate a CycloneDX SBOM")
    sbom.add_argument("scan_id")
    sbom.add_argument("--format", choices=["json", "xml"], default="json")
    sbom.add_argument("--output", required=True)
    sbom.set_defaults(func=cmd_sbom)

    compare = sub.add_parser("compare", help="Compare two scans")
    compare.add_argument("scan_a")
    compare.add_argument("scan_b")
    compare.add_argument("--output")
    compare.set_defaults(func=cmd_compare)

    serve = sub.add_parser("serve", help="Start the API server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=cmd_serve)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
