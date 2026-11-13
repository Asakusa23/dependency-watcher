export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
export type InspectionStatus = "VULNERABLE" | "CHECKED" | "UNKNOWN" | "ERROR";
export type ScanStatus = "pending" | "running" | "completed" | "failed";
export type SourceType = "local" | "upload" | "github";

export interface ScanSummary {
  id: string;
  project_name: string;
  source_type: SourceType;
  source_reference: string | null;
  status: ScanStatus;
  phase: string;
  progress: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  security_score: number | null;
  score_grade: string | null;
  score_breakdown: Record<string, unknown> | null;
  coverage_percent: number | null;
  total_dependencies: number;
  direct_dependencies: number;
  transitive_dependencies: number;
  checked_dependencies: number;
  unknown_dependencies: number;
  vulnerable_dependencies: number;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  outdated_count: number;
  unpinned_count: number;
  deprecated_count: number;
  ecosystems: string[];
  error_message: string | null;
}

export interface ScanDetail extends ScanSummary {
  dependency_files: string[];
  warnings: string[];
  errors: string[];
  sources_used: string[];
  sbom_serial: string | null;
  message?: string;
}

export interface Dependency {
  id: number;
  scan_id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl: string | null;
  version_specifier: string | null;
  pinned: boolean;
  direct: boolean;
  scope: string | null;
  source_files: string[];
  license: string | null;
  latest_version: string | null;
  latest_release_date: string | null;
  outdated: boolean;
  deprecated: boolean;
  deprecation_reason: string | null;
  vulnerability_count: number;
  max_severity: Severity | null;
  priority_level: Severity;
  priority_score: number;
  inspection_status: InspectionStatus;
  inspection_message: string | null;
  health_status: string;
  risk_flags: string[];
  risk_reasons: string[];
  vulnerabilities?: Vulnerability[];
}

export interface Vulnerability {
  id: number;
  scan_id: string;
  dependency_id: number;
  osv_id: string;
  aliases: string[];
  cve_ids: string[];
  ghsa_ids: string[];
  summary: string | null;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_version: string | null;
  published: string | null;
  modified: string | null;
  withdrawn: string | null;
  fixed_versions: string[];
  affected_versions: string[];
  references: Array<{ type?: string; url: string } | string>;
  source: string;
  priority_level: Severity;
  priority_score: number;
  priority_reasons: string[];
  dependency_name: string | null;
  dependency_version: string | null;
  dependency_ecosystem: string | null;
  dependency_direct: boolean | null;
  details?: string | null;
  database_specific?: Record<string, unknown>;
}

export interface Paged<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface RemediationRecommendation {
  dependency_id: number;
  package: string;
  ecosystem: string;
  current_version: string;
  recommended_version: string;
  direct: boolean;
  severity: Severity;
  priority_level: Severity;
  priority_score: number;
  advisories: string[];
  reasons: string[];
  conflicts: string[];
  breaking_risk: "major" | "low" | "unknown";
  action: "upgrade" | "manual_review";
}

export interface MaintenanceUpdate {
  dependency_id: number;
  package: string;
  ecosystem: string;
  current_version: string;
  latest_version: string;
  direct: boolean;
  breaking_risk: "major" | "low" | "unknown";
}

export interface Remediation {
  scan_id: string;
  generated_at: string | null;
  summary: {
    urgent_upgrades: number;
    total_recommendations: number;
    unfixable: number;
    maintenance_updates: number;
    multi_version_packages: Record<string, string[]>;
  };
  recommendations: RemediationRecommendation[];
  maintenance_updates: MaintenanceUpdate[];
  notice: string;
}

export interface CompareResult {
  scan_a: ScanSummary;
  scan_b: ScanSummary;
  delta: {
    dependencies: number;
    vulnerabilities: number;
    critical: number;
    high: number;
    security_score: number | null;
  };
  dependencies: {
    added: DependencyBrief[];
    removed: DependencyBrief[];
    version_changed: Array<{
      ecosystem: string;
      name: string;
      old_versions: string[];
      new_versions: string[];
    }>;
    unchanged_count: number;
  };
  vulnerabilities: {
    new: Vulnerability[];
    resolved: Vulnerability[];
    persisted_count: number;
  };
}

export interface DependencyBrief {
  ecosystem: string;
  name: string;
  version: string;
  direct: boolean;
  inspection_status: InspectionStatus;
  max_severity: Severity | null;
}

export interface Settings {
  allow_local_paths: boolean;
  enable_osv: boolean;
  enable_registry: boolean;
  enable_nvd: boolean;
  enable_github: boolean;
  http_timeout_seconds: number;
  cache_ttl_seconds: number;
  nvd_api_key_configured: boolean;
  github_token_configured: boolean;
}

export interface SettingsUpdate extends Partial<Settings> {
  nvd_api_key?: string;
  github_token?: string;
  clear_nvd_api_key?: boolean;
  clear_github_token?: boolean;
}

export interface Meta {
  version: string;
  ecosystems: string[];
  dependency_files: string[];
  limits: {
    max_upload_bytes: number;
    max_archive_files: number;
    max_extracted_bytes: number;
    max_project_files: number;
    max_dependencies: number;
  };
}

export interface Health {
  status: string;
  version: string;
  database: string;
  sources: Record<string, string>;
}

export interface CreateScanInput {
  source_type: "local" | "github";
  path?: string;
  repository_url?: string;
  project_name?: string;
}
