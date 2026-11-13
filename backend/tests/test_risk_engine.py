from __future__ import annotations

from datetime import datetime, timezone

from app.risk_engine.engine import (
    RiskEngine,
    highest_priority,
    max_severity,
    security_score,
    severity_sort_key,
)
from app.vulnerability_engine.osv import OsvVulnerability


def test_cvss_is_used_but_dw_priority_is_separate() -> None:
    vulnerability = OsvVulnerability(
        osv_id="CVE-2026-0001",
        severity="HIGH",
        cvss_score=9.1,
        fixed_versions=["2.0.0"],
        published="2026-01-01T00:00:00Z",
    )
    assessment = RiskEngine().assess_vulnerability(
        vulnerability,
        direct=True,
        today=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    assert assessment.level == "CRITICAL"
    assert "not an official CVSS score" in assessment.reasons[0]
    assert any("Official CVSS base score 9.1" in reason for reason in assessment.reasons)


def test_vulnerability_with_unknown_severity_gets_neutral_base() -> None:
    assessment = RiskEngine().assess_vulnerability(
        OsvVulnerability(osv_id="OSV-2026-1"),
        direct=False,
    )
    assert assessment.score < 50
    assert any("neutral base score" in reason for reason in assessment.reasons)


def test_dependency_assessment_prefers_highest_vulnerability() -> None:
    engine = RiskEngine()
    low = engine.assess_vulnerability(OsvVulnerability(osv_id="a", severity="LOW"), direct=True)
    critical = engine.assess_vulnerability(OsvVulnerability(osv_id="b", severity="CRITICAL"), direct=True)
    result = engine.assess_dependency(
        vulnerabilities=[
            (OsvVulnerability(osv_id="a", severity="LOW"), low),
            (OsvVulnerability(osv_id="b", severity="CRITICAL"), critical),
        ],
        deprecated=True,
        outdated=True,
        pinned=True,
        direct=True,
    )
    assert result.level == "CRITICAL"
    assert any("Aggregated from 2 vulnerabilities" in reason for reason in result.reasons)


def test_unpinned_dependency_is_not_reported_as_safe() -> None:
    result = RiskEngine().assess_dependency(
        vulnerabilities=[],
        deprecated=False,
        outdated=False,
        pinned=False,
        direct=True,
    )
    assert result.level == "LOW"
    assert "could not be performed" in result.reasons[0]


def test_security_score_penalizes_vulnerabilities_and_coverage() -> None:
    vulnerable = security_score(
        total=10,
        checked=10,
        critical=2,
        high=1,
        medium=0,
        low=0,
        info=0,
        outdated=1,
        deprecated=0,
    )
    incomplete = security_score(
        total=10,
        checked=5,
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        outdated=0,
        deprecated=0,
    )
    empty = security_score(
        total=0,
        checked=0,
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        outdated=0,
        deprecated=0,
    )
    assert vulnerable.score == 0.0
    assert vulnerable.grade == "F"
    assert incomplete.breakdown["coverage_percent"] == 50.0
    assert incomplete.score == 67.5
    assert empty.score is None
    assert empty.grade == "N/A"


def test_sorting_helpers() -> None:
    assert max_severity(["LOW", "CRITICAL", "HIGH"]) == "CRITICAL"
    assert max_severity([]) == "NONE"
    assert highest_priority(["INFO", "HIGH", "LOW"]) == "HIGH"
    assert sorted(["LOW", "CRITICAL", "UNKNOWN"], key=severity_sort_key) == [
        "CRITICAL",
        "LOW",
        "UNKNOWN",
    ]
