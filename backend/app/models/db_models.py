from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONText, UTCDateTime, utcnow


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    project_name: Mapped[str] = mapped_column(String(255), index=True)
    source_type: Mapped[str] = mapped_column(String(32))
    source_reference: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    phase: Mapped[str] = mapped_column(String(64), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    security_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    score_grade: Mapped[Optional[str]] = mapped_column(String(4), nullable=True)
    score_breakdown: Mapped[Optional[dict]] = mapped_column(JSONText, nullable=True)
    coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)

    total_dependencies: Mapped[int] = mapped_column(Integer, default=0)
    direct_dependencies: Mapped[int] = mapped_column(Integer, default=0)
    transitive_dependencies: Mapped[int] = mapped_column(Integer, default=0)
    checked_dependencies: Mapped[int] = mapped_column(Integer, default=0)
    unknown_dependencies: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_dependencies: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    outdated_count: Mapped[int] = mapped_column(Integer, default=0)
    unpinned_count: Mapped[int] = mapped_column(Integer, default=0)
    deprecated_count: Mapped[int] = mapped_column(Integer, default=0)

    dependency_files: Mapped[list] = mapped_column(JSONText, default=list)
    ecosystems: Mapped[list] = mapped_column(JSONText, default=list)
    warnings: Mapped[list] = mapped_column(JSONText, default=list)
    errors: Mapped[list] = mapped_column(JSONText, default=list)
    sources_used: Mapped[list] = mapped_column(JSONText, default=list)
    scan_metadata: Mapped[dict] = mapped_column(JSONText, default=dict)
    sbom_serial: Mapped[str] = mapped_column(String(64), default="")
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    dependencies: Mapped[list["Dependency"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Dependency.name"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Vulnerability.osv_id"
    )


class Dependency(Base):
    __tablename__ = "dependencies"
    __table_args__ = (
        UniqueConstraint("scan_id", "ecosystem", "name", "version", name="uq_dependency_scan_package"),
        Index("ix_dependency_scan_ecosystem", "scan_id", "ecosystem"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(512), index=True)
    version: Mapped[str] = mapped_column(String(255), default="")
    version_specifier: Mapped[str] = mapped_column(String(255), default="")
    purl: Mapped[str] = mapped_column(String(1024), default="")
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    direct: Mapped[bool] = mapped_column(Boolean, default=False)
    scope: Mapped[str] = mapped_column(String(32), default="runtime")
    source_files: Mapped[list] = mapped_column(JSONText, default=list)

    license: Mapped[str] = mapped_column(String(255), default="")
    latest_version: Mapped[str] = mapped_column(String(255), default="")
    latest_release_date: Mapped[str] = mapped_column(String(64), default="")
    outdated: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecation_reason: Mapped[str] = mapped_column(Text, default="")

    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    max_severity: Mapped[str] = mapped_column(String(16), default="NONE")
    priority_level: Mapped[str] = mapped_column(String(16), default="INFO")
    priority_score: Mapped[float] = mapped_column(Float, default=0.0)
    inspection_status: Mapped[str] = mapped_column(String(24), default="PENDING", index=True)
    inspection_message: Mapped[str] = mapped_column(Text, default="")
    health_status: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    risk_flags: Mapped[list] = mapped_column(JSONText, default=list)
    risk_reasons: Mapped[list] = mapped_column(JSONText, default=list)
    checked_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="dependencies")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="dependency", cascade="all, delete-orphan", order_by="Vulnerability.cvss_score.desc()"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("scan_id", "dependency_id", "osv_id", name="uq_vulnerability_scan_dep_osv"),
        Index("ix_vulnerability_scan_severity", "scan_id", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    dependency_id: Mapped[int] = mapped_column(ForeignKey("dependencies.id", ondelete="CASCADE"), index=True)
    osv_id: Mapped[str] = mapped_column(String(64), index=True)
    aliases: Mapped[list] = mapped_column(JSONText, default=list)
    cve_ids: Mapped[list] = mapped_column(JSONText, default=list)
    ghsa_ids: Mapped[list] = mapped_column(JSONText, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(255), default="")
    cvss_version: Mapped[str] = mapped_column(String(16), default="")
    published: Mapped[str] = mapped_column(String(64), default="")
    modified: Mapped[str] = mapped_column(String(64), default="")
    withdrawn: Mapped[str] = mapped_column(String(64), default="")
    fixed_versions: Mapped[list] = mapped_column(JSONText, default=list)
    affected_versions: Mapped[list] = mapped_column(JSONText, default=list)
    references: Mapped[list] = mapped_column(JSONText, default=list)
    source: Mapped[str] = mapped_column(String(64), default="OSV.dev")
    priority_level: Mapped[str] = mapped_column(String(16), default="INFO")
    priority_score: Mapped[float] = mapped_column(Float, default=0.0)
    priority_reasons: Mapped[list] = mapped_column(JSONText, default=list)
    database_specific: Mapped[dict] = mapped_column(JSONText, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="vulnerabilities")
    dependency: Mapped[Dependency] = relationship(back_populates="vulnerabilities")
