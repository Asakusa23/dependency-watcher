import { useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  CheckCircle2,
  CircleGauge,
  FileWarning,
  GitBranch,
  PackageSearch,
  Plus,
  Radar,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Timer,
} from "lucide-react";
import { useScans } from "@/context/ScanContext";
import { useScanDetail } from "@/hooks/useApiData";
import { useApiResource } from "@/hooks/useApiResource";
import { api } from "@/lib/api";
import { formatDate, formatDuration, percent, relativeTime } from "@/lib/format";
import { PageHeader, ErrorState, LoadingBlock, Skeleton } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatCard } from "@/components/StatCard";
import { SeverityBadge, GradeBadge, ScanStatusBadge } from "@/components/ui/badges";
import { Progress } from "@/components/ui/table";
import { SeverityDonut, EcosystemBars, HistoryChart, ScoreGauge } from "@/components/charts/Charts";
import { ScanTable } from "@/components/scans/ScanTable";
import { NewScanDialog } from "@/components/scans/NewScanDialog";
import type { Dependency, ScanSummary, Vulnerability } from "@/types";
import { cn } from "@/lib/utils";

export function DashboardPage() {
  const { scans, activeScan, loading, error, refresh, refreshing } = useScans();
  const [newScanOpen, setNewScanOpen] = useState(false);
  const detail = useScanDetail(activeScan?.id);
  const deps = useApiResource<{ items: Dependency[]; total: number }>(
    () => api.dependencies(activeScan!.id, { limit: 5000 }),
    activeScan?.id ?? "none",
    { enabled: Boolean(activeScan) },
  );
  const vulns = useApiResource<{ items: Vulnerability[]; total: number }>(
    () => api.vulnerabilities(activeScan!.id, { limit: 5000 }),
    activeScan?.id ?? "none",
    { enabled: Boolean(activeScan) },
  );
  const remediation = useApiResource(
    () => api.remediation(activeScan!.id),
    activeScan?.id ?? "none",
    { enabled: Boolean(activeScan && activeScan.status === "completed") },
  );

  if (loading && !scans.length) {
    return <DashboardSkeleton />;
  }

  if (error && !scans.length) {
    return (
      <div className="space-y-6">
        <PageHeader eyebrow="Security posture" title="Supply chain overview" />
        <ErrorState message={error} onRetry={() => void refresh()} />
      </div>
    );
  }

  if (!scans.length) {
    return (
      <>
        <Onboarding onNewScan={() => setNewScanOpen(true)} />
        <NewScanDialog open={newScanOpen} onOpenChange={setNewScanOpen} />
      </>
    );
  }

  const scan = activeScan ?? scans[0];
  const detailData = detail.data;
  const completed = scans.filter((item) => item.status === "completed");
  const vulnerable = vulns.data?.items ?? [];
  const ecosystemMap = new Map<string, number>();
  for (const vuln of vulnerable) {
    if (vuln.dependency_ecosystem) {
      ecosystemMap.set(vuln.dependency_ecosystem, (ecosystemMap.get(vuln.dependency_ecosystem) ?? 0) + 1);
    }
  }
  const ecosystemData = [...ecosystemMap.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
  const coverage = scan.coverage_percent ?? 0;
  const isLive = scan.status === "running" || scan.status === "pending";
  const recommendations = remediation.data?.recommendations.slice(0, 3) ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Security posture"
        title="Supply chain overview"
        description={
          scan.status === "completed"
            ? `${scan.project_name} · scanned ${relativeTime(scan.completed_at)} · ${formatDuration(scan.duration_seconds)}`
            : `${scan.project_name} · scan ${scan.status}`
        }
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void refresh()}
              disabled={refreshing}
              title="Refresh scans"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
              <span className="hidden sm:inline">Refresh</span>
            </Button>
            <Button size="sm" onClick={() => setNewScanOpen(true)}>
              <Plus className="h-4 w-4" />
              New scan
            </Button>
          </>
        }
      />

      {error && (
        <ErrorState
          message={`${error} Showing the most recent cached state.`}
          onRetry={() => void refresh()}
        />
      )}

      {isLive && (
        <Card className="border-blue-500/25 bg-blue-500/[0.04]">
          <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="flex items-center gap-3">
              <div className="rounded-lg border border-blue-500/25 bg-blue-500/10 p-2 text-blue-300">
                <Radar className="h-5 w-5 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
                  Scan in progress
                  <ScanStatusBadge status={scan.status} />
                </div>
                <p className="mt-0.5 text-xs text-muted">{scan.phase}</p>
              </div>
            </div>
            <div className="flex-1 sm:px-6">
              <Progress value={scan.progress} />
            </div>
            <span className="font-mono text-sm text-blue-300">{Math.round(scan.progress)}%</span>
          </CardContent>
        </Card>
      )}

      {(detailData?.errors.length || detailData?.warnings.length) && (
        <div className="space-y-2">
          {detailData.errors.map((message) => (
            <div key={message} className="flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/[0.05] px-4 py-2.5 text-xs text-red-200/80">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {message}
            </div>
          ))}
          {detailData.warnings.map((message) => (
            <div key={message} className="flex items-start gap-2 rounded-lg border border-amber-500/15 bg-amber-500/[0.04] px-4 py-2.5 text-xs text-amber-200/75">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {message}
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard
          label="Components"
          value={scan.total_dependencies}
          hint={`${scan.direct_dependencies} direct · ${scan.transitive_dependencies} transitive`}
          icon={Boxes}
          tone="accent"
        />
        <StatCard
          label="Vulnerabilities"
          value={scan.vulnerability_count}
          hint={`${scan.vulnerable_dependencies} affected components`}
          icon={ShieldAlert}
          tone={scan.vulnerability_count ? "danger" : "success"}
        />
        <StatCard
          label="Critical + high"
          value={scan.critical_count + scan.high_count}
          hint={`${scan.critical_count} critical · ${scan.high_count} high`}
          icon={FileWarning}
          tone={scan.critical_count + scan.high_count ? "warning" : "success"}
        />
        <StatCard
          label="Checked coverage"
          value={percent(coverage)}
          hint={`${scan.checked_dependencies}/${scan.total_dependencies} · ${scan.unknown_dependencies} unverified`}
          icon={CircleGauge}
          tone={coverage >= 95 ? "success" : coverage >= 75 ? "warning" : "danger"}
        />
        <StatCard
          label="Outdated"
          value={scan.outdated_count}
          hint={`${scan.unpinned_count} unpinned · ${scan.deprecated_count} deprecated`}
          icon={PackageSearch}
          tone="default"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        <Card className="xl:col-span-4">
          <CardHeader>
            <div>
              <CardTitle>Security score</CardTitle>
              <CardDescription>Proprietary exposure score, not CVSS.</CardDescription>
            </div>
            <GradeBadge score={scan.security_score} grade={scan.score_grade} />
          </CardHeader>
          <CardContent>
            <ScoreGauge score={scan.security_score} grade={scan.score_grade} />
            <div className="mt-1 space-y-2">
              <div className="flex justify-between text-[11px]">
                <span className="text-slate-500">Inspection coverage</span>
                <span className="font-mono text-slate-300">{percent(coverage)}</span>
              </div>
              <Progress value={coverage} className="h-1" />
              <div className="flex justify-between text-[11px]">
                <span className="text-slate-500">Confidence multiplier</span>
                <span className="font-mono text-slate-300">
                  {String((scan.score_breakdown as { coverage_multiplier?: number } | null)?.coverage_multiplier ?? "—")}
                </span>
              </div>
            </div>
            <p className="mt-3 border-t border-border/70 pt-3 text-[10px] leading-relaxed text-slate-600">
              Score = (100 − vulnerability penalty − health penalty) × (0.35 + 0.65 × coverage). Unchecked
              components reduce confidence instead of being treated as safe.
            </p>
          </CardContent>
        </Card>

        <Card className="xl:col-span-4">
          <CardHeader>
            <div>
              <CardTitle>Severity distribution</CardTitle>
              <CardDescription>Normalized advisory severity across findings.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <SeverityDonut scan={scan} />
          </CardContent>
        </Card>

        <Card className="xl:col-span-4">
          <CardHeader>
            <div>
              <CardTitle>Findings by ecosystem</CardTitle>
              <CardDescription>Where advisories concentrate in this project.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {vulns.loading && !vulns.data ? (
              <Skeleton className="h-[200px] w-full" />
            ) : (
              <EcosystemBars data={ecosystemData} />
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        <Card className="xl:col-span-8">
          <CardHeader>
            <div>
              <CardTitle>Posture over time</CardTitle>
              <CardDescription>Security score and finding volume across recent completed scans.</CardDescription>
            </div>
            <Sparkles className="h-4 w-4 text-slate-600" />
          </CardHeader>
          <CardContent>
            <HistoryChart scans={completed} />
          </CardContent>
        </Card>

        <Card className="xl:col-span-4">
          <CardHeader>
            <div>
              <CardTitle>Priority actions</CardTitle>
              <CardDescription>Highest-ranked upgrade recommendations.</CardDescription>
            </div>
            <Link to={`/scans/${scan.id}`} className="text-[11px] text-blue-400 hover:text-blue-300">
              View scan
            </Link>
          </CardHeader>
          <CardContent className="space-y-2">
            {remediation.loading && !remediation.data ? (
              <>
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
              </>
            ) : recommendations.length ? (
              recommendations.map((item) => (
                <Link
                  key={item.dependency_id}
                  to={`/scans/${scan.id}`}
                  className="block rounded-lg border border-border bg-surface/60 p-3 transition-colors hover:border-slate-500"
                >
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={item.severity} dot />
                    <span className="min-w-0 flex-1 truncate text-xs font-medium text-slate-200">{item.package}</span>
                    <span className="font-mono text-[10px] text-slate-500">P{item.priority_score}</span>
                  </div>
                  <div className="mt-1.5 flex items-center gap-1.5 font-mono text-[10px]">
                    <span className="text-slate-500">{item.current_version || "unpinned"}</span>
                    <ArrowRight className="h-2.5 w-2.5 text-slate-700" />
                    <span className={item.recommended_version ? "text-emerald-300" : "text-amber-400"}>
                      {item.recommended_version || "manual review"}
                    </span>
                    {!item.direct && <span className="ml-auto text-[9px] text-slate-600">transitive</span>}
                  </div>
                </Link>
              ))
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <CheckCircle2 className="h-6 w-6 text-emerald-400/80" />
                <p className="mt-2 text-xs font-medium text-slate-300">No advisory-driven upgrades</p>
                <p className="mt-1 text-[10px] text-slate-600">
                  {scan.unknown_dependencies > 0
                    ? `${scan.unknown_dependencies} component(s) remain unverified.`
                    : "All components were checked against OSV."}
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Recent scans</CardTitle>
            <CardDescription>Every scan is stored locally with its evidence and reports.</CardDescription>
          </div>
          <Link to="/scans" className="text-[11px] text-blue-400 hover:text-blue-300">
            All scans
          </Link>
        </CardHeader>
        <div className="overflow-hidden rounded-b-xl">
          <ScanTable scans={scans.slice(0, 5)} compact />
        </div>
        <div className="flex items-center justify-between border-t border-border px-5 py-2 text-[10px] text-slate-600">
          <span>{completed.length} completed scans in local history</span>
          <span className="inline-flex items-center gap-1"><Timer className="h-3 w-3" /> full results retained</span>
        </div>
      </Card>

      <NewScanDialog open={newScanOpen} onOpenChange={setNewScanOpen} />
    </div>
  );
}

function Onboarding({ onNewScan }: { onNewScan: () => void }) {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Welcome"
        title="Know what your project ships"
        description="Dependency Watcher scans manifests across four ecosystems, checks OSV.dev advisories, enriches package health, and produces evidence you can share."
        actions={
          <Button onClick={onNewScan}>
            <Plus className="h-4 w-4" />
            Start first scan
          </Button>
        }
      />
      <div className="grid gap-4 lg:grid-cols-12">
        <Card className="relative overflow-hidden lg:col-span-7">
          <div className="grid-noise absolute inset-0 opacity-60" />
          <CardContent className="relative py-10">
            <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/25 bg-blue-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-blue-300">
              <ShieldCheck className="h-3 w-3" />
              Local-first supply chain analysis
            </div>
            <h2 className="mt-5 max-w-lg text-3xl font-semibold leading-tight tracking-tight text-white">
              From manifests to a defensible security posture in one scan.
            </h2>
            <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted">
              Scan a local directory, a ZIP archive, or a public GitHub repository. Source code stays on
              your machine; only package coordinates are sent to vulnerability sources.
            </p>
            <div className="mt-6 flex flex-wrap gap-2">
              <Button onClick={onNewScan}>
                <Radar className="h-4 w-4" />
                Run a scan
              </Button>
              <Link to="/settings" className="inline-flex h-10 items-center gap-2 rounded-lg border border-border bg-elevated px-4 text-sm text-slate-300 hover:border-slate-500">
                Configure sources
              </Link>
            </div>
            <div className="mt-8 grid gap-2 text-[11px] text-slate-500 sm:grid-cols-3">
              {[
                ["PyPI", "requirements, pyproject, lockfiles"],
                ["npm", "package + npm/pnpm/yarn locks"],
                ["Maven / Rust", "pom.xml, Gradle, Cargo"],
              ].map(([title, body]) => (
                <div key={title} className="rounded-lg border border-border/70 bg-background/40 p-3">
                  <div className="font-medium text-slate-300">{title}</div>
                  <div className="mt-1 leading-relaxed text-slate-600">{body}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4 lg:col-span-5">
          <Card>
            <CardHeader>
              <div>
                <CardTitle>What gets produced</CardTitle>
                <CardDescription>Real evidence, not a simulated demo state.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                [ShieldAlert, "Vulnerability findings", "OSV advisories with CVSS, aliases, ranges and fixed versions."],
                [CircleGauge, "Risk and coverage", "Separate proprietary priority plus explicit unverified components."],
                [GitBranch, "Remediation plan", "Upgrade targets, breaking-change warnings and dependency conflicts."],
                [FileWarning, "Portable outputs", "CycloneDX 1.5 SBOM, PDF, HTML, JSON and CSV reports."],
              ].map(([Icon, title, body]) => {
                const ItemIcon = Icon as typeof ShieldAlert;
                return (
                  <div key={String(title)} className="flex gap-3">
                    <div className="mt-0.5 rounded-md border border-border bg-surface p-1.5 text-slate-500">
                      <ItemIcon className="h-3.5 w-3.5" />
                    </div>
                    <div>
                      <div className="text-xs font-medium text-slate-300">{String(title)}</div>
                      <div className="mt-0.5 text-[11px] leading-relaxed text-slate-600">{String(body)}</div>
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
          <div className="rounded-xl border border-border bg-surface/70 p-4">
            <p className="eyebrow">Prefer the terminal?</p>
            <code className="mt-2 block rounded-md border border-border bg-background px-3 py-2 font-mono text-[11px] text-blue-300">
              python cli/dw.py scan .
            </code>
            <p className="mt-2 text-[10px] leading-relaxed text-slate-600">
              The CLI uses the same scan engine, report service and local database as the API.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Security posture" title="Supply chain overview" />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {Array.from({ length: 5 }).map((_, index) => (
          <Skeleton key={index} className="h-[104px] w-full" />
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        {Array.from({ length: 3 }).map((_, index) => (
          <Skeleton key={index} className="h-[340px] w-full" />
        ))}
      </div>
      <LoadingBlock label="Loading security posture" />
    </div>
  );
}
