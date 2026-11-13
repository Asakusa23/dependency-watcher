from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.vulnerability_engine.osv import OsvVulnerability


SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}
PRIORITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
SEVERITY_BASE = {"CRITICAL": 95.0, "HIGH": 80.0, "MEDIUM": 55.0, "LOW": 25.0, "INFO": 5.0, "UNKNOWN": 50.0}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


@dataclass
class RiskAssessment:
    level: str
    score: float
    reasons: list[str] = field(default_factory=list)


@dataclass
class SecurityScore:
    score: float | None
    grade: str
    breakdown: dict


class RiskEngine:
    """Produces a transparent remediation priority, separate from official CVSS/severity."""

    def assess_vulnerability(
        self,
        vulnerability: OsvVulnerability,
        *,
        direct: bool,
        today: datetime | None = None,
    ) -> RiskAssessment:
        reasons: list[str] = []
        if vulnerability.cvss_score is not None:
            score = vulnerability.cvss_score * 10.0
            reasons.append(f"Official CVSS base score {vulnerability.cvss_score:.1f} contributes {score:.0f}/100")
        else:
            score = SEVERITY_BASE.get(vulnerability.severity, 50.0)
            if vulnerability.severity == "UNKNOWN":
                reasons.append("No official CVSS or severity is available; neutral base score used")
            else:
                reasons.append(f"Official severity {vulnerability.severity} maps to a base of {score:.0f}/100")
        if direct:
            score += 8
            reasons.append("Direct dependency (+8 exposure)")
        else:
            score -= 8
            reasons.append("Transitive dependency (-8 exposure)")

        if vulnerability.fixed_versions:
            score += 5
            reasons.append(f"Fixed version available ({vulnerability.fixed_versions[0]}) (+5 actionability)")
        else:
            reasons.append("No fixed version listed by the source")

        if vulnerability.published:
            published = _parse_date(vulnerability.published)
            if published:
                now = today or datetime.now(timezone.utc)
                age_days = max(0, (now - published).days)
                if age_days <= 30:
                    score += 6
                    reasons.append(f"Published {age_days} days ago (+6 recency)")
                elif age_days <= 365:
                    reasons.append(f"Published {age_days} days ago (no age adjustment)")
                elif age_days >= 730:
                    score -= 4
                    reasons.append(f"Published {age_days} days ago (-4 age)")
            else:
                reasons.append("Publication date could not be parsed")
        else:
            reasons.append("Publication date is not provided by the source")

        score = round(max(0.0, min(100.0, score)), 1)
        level = _priority_from_score(score)
        reasons.insert(0, f"Dependency Watcher priority {level} ({score:.1f}/100); this is not an official CVSS score")
        return RiskAssessment(level=level, score=score, reasons=reasons)

    def assess_dependency(
        self,
        *,
        vulnerabilities: list[tuple[OsvVulnerability, RiskAssessment]],
        deprecated: bool,
        outdated: bool,
        pinned: bool,
        direct: bool,
    ) -> RiskAssessment:
        if vulnerabilities:
            best_vuln, best = max(vulnerabilities, key=lambda item: item[1].score)
            reasons = list(best.reasons)
            if len(vulnerabilities) > 1:
                reasons.append(f"Aggregated from {len(vulnerabilities)} vulnerabilities; highest priority shown")
            return RiskAssessment(level=best.level, score=best.score, reasons=reasons)
        if deprecated:
            return RiskAssessment(
                level="MEDIUM",
                score=55.0,
                reasons=["Registry metadata explicitly marks the release as deprecated"],
            )
        if not pinned:
            return RiskAssessment(
                level="LOW",
                score=25.0,
                reasons=["Dependency version is not pinned, so vulnerability matching could not be performed"],
            )
        if outdated:
            return RiskAssessment(
                level="LOW",
                score=20.0,
                reasons=["A newer version is available; no known vulnerabilities were found for the current version"],
            )
        return RiskAssessment(
            level="INFO",
            score=5.0,
            reasons=["No known vulnerabilities or health issues detected" if direct else "No known vulnerabilities detected"],
        )


def security_score(
    *,
    total: int,
    checked: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    info: int,
    outdated: int,
    deprecated: int,
) -> SecurityScore:
    if total <= 0:
        return SecurityScore(
            score=None,
            grade="N/A",
            breakdown={
                "formula": "No dependencies were discovered",
                "total_dependencies": total,
            },
        )
    coverage = max(0.0, min(1.0, checked / total))
    health_penalty = min(10.0, outdated * 0.5 + deprecated * 2)
    if critical or high:
        vulnerability_penalty = 100.0
        raw = 0.0
        severity_policy = (
            "A confirmed HIGH or CRITICAL advisory forces the score to 0 until it is remediated"
        )
    else:
        vulnerability_penalty = medium * 8 + low * 3 + info * 1
        raw = max(0.0, 100.0 - min(100.0, vulnerability_penalty) - health_penalty)
        severity_policy = (
            "No HIGH or CRITICAL advisories; MEDIUM/LOW/INFO and health penalties apply"
        )
    confidence_multiplier = 0.35 + 0.65 * coverage
    value = round(raw * confidence_multiplier, 1)
    grade = _grade(value)
    return SecurityScore(
        score=value,
        grade=grade,
        breakdown={
            "formula": "score = (100 - vulnerability_penalty - health_penalty) x (0.35 + 0.65 x coverage)",
            "severity_policy": severity_policy,
            "coverage_percent": round(coverage * 100, 1),
            "checked_dependencies": checked,
            "total_dependencies": total,
            "vulnerability_penalty": round(min(100.0, vulnerability_penalty), 1),
            "health_penalty": round(health_penalty, 1),
            "raw_score_before_coverage": round(raw, 1),
            "coverage_multiplier": round(confidence_multiplier, 3),
            "final_score": value,
            "grade": grade,
            "note": "This proprietary security score is not a CVSS score. Unverified dependencies reduce confidence.",
        },
    )


def max_severity(severities: list[str]) -> str:
    if not severities:
        return "NONE"
    return max(severities, key=lambda value: SEVERITY_ORDER.get(value, 0))


def highest_priority(levels: list[str]) -> str:
    if not levels:
        return "INFO"
    return max(levels, key=lambda value: PRIORITY_ORDER.get(value, 0))


def severity_sort_key(value: str) -> int:
    return SEVERITY_RANK.get(value, 9)


def _priority_from_score(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    if score >= 40:
        return "E"
    return "F"


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    cleaned = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        try:
            parsed = datetime.strptime(cleaned[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
