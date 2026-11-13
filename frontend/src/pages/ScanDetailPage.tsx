import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  Boxes,
  Check,
  Copy,
  Download,
  FileCheck2,
  FileWarning,
  Fingerprint,
  PackageOpen,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Timer,
  Wrench,
} from "lucide-react";
import { useScanDetail } from "@/hooks/useApiData";
import { PageHeader, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { GradeBadge, ScanStatusBadge, SeverityBadge } from "@/components/ui/badges";
import { Progress } from "@/components/ui/table";
import { StatCard } from "@/components/StatCard";
import { ScoreGauge, SeverityDonut } from "@/components/charts/Charts";
import { DependencyExplorer } from "@/components/dependencies/DependencyExplorer";
import { VulnerabilityExplorer } from "@/components/vulnerabilities/VulnerabilityExplorer";
import { RemediationPanel } from "@/components/scans/RemediationPanel";
import { ReportsPanel } from "@/components/scans/ReportsPanel";
import { reportUrl } from "@/lib/api";
import { formatDate, formatDuration, percent } from "@/lib/format";
import type { ScanDetail } from "@/types";

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const resource = useScanDetail(scanId);
  const [tab, setTab] = useState("overview");
  const [copied, setCopied] = useState(false);

  if (resource.loading && !resource.data) {
    return <LoadingBlock label="Loading scan result" />;
  }
  if (resource.error && !resource.data) {
    return (
      <div className="space-y-6">
        <Link to="/scans" className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white">
          <ArrowLeft className="h-3.5 w-3.5" />
          Scan history
        </Link>
        <ErrorState message={resource.error} onRetry={resource.reload} />
      </div>
    );
  }
  const scan = resource.data;
  if (!scan) return null;

  const live = scan.status === "pending" || scan.status === "running";
  const copyId = async () => {
    try {
      await navigator.clipboard.writeText(scan.id);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link to="/scans" className="mb-3 inline-flex items-center gap-1.5 text-[11px] text-slate-500 hover:text-slate-200">
            <ArrowLeft className="h-3 w-3" />
            Back to scans
          </Link>
          <div className="flex flex-wrap items-center gap-2">
            <ScanStatusBadge status={scan.status} />
            <GradeBadge score={scan.security_score} grade={scan.score_grade} />
            <button
              onClick={() => void copyId()}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-[9px] text-slate-500 hover:text-slate-300"
              title="Copy scan ID"
            >
              {scan.id.slice(0, 12)}
              {copied ? <Check className="h-2.5 w-2.5 text-emerald-400" /> : <Copy className="h-2.5 w-2.5" />}
            </button>
          </div>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white">{scan.project_name}</h1>
          <p className="mt-1 max-w-3xl truncate text-xs text-muted" title={scan.source_reference ?? undefined}>
            {scan.source_type} · {scan.source_reference ?? "—"} · {formatDate(scan.created_at)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={resource.reload} disabled={resource.loading}>
            <RefreshCw className={`h-3.5 w-3.5 ${resource.loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          {scan.status === "completed" && (
            <a
              href={reportUrl(scan.id, "pdf")}
              download
              className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-blue-600 px-3 text-xs font-medium text-white hover:bg-blue-500"
            >
              <Download className="h-3.5 w-3.5" />
              PDF report
            </a>
          )}
        </div>
      </div>

      {live && (
        <Card className="border-blue-500/25 bg-blue-500/[0.03]">
          <CardContent>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-slate-200">Analysis in progress</div>
                <p className="mt-0.5 text-xs text-muted">{scan.phase}</p>
              </div>
              <span className="font-mono text-lg text-blue-300">{Math.round(scan.progress)}%</span>
            </div>
            <Progress value={scan.progress} className="mt-3" />
          </CardContent>
        </Card>
      )}

      {scan.status === "failed" && (
        <ErrorState message={scan.error_message || "The scan failed before completing."} onRetry={resource.reload} />
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard label="Components" value={scan.total_dependencies} hint={`${scan.direct_dependencies} direct`} icon={Boxes} tone="accent" />
        <StatCard label="Findings" value={scan.vulnerability_count} hint={`${scan.vulnerable_dependencies} affected`} icon={ShieldAlert} tone={scan.vulnerability_count ? "danger" : "success"} />
        <StatCard label="Critical + high" value={scan.critical_count + scan.high_count} hint={`${scan.critical_count} critical`} icon={FileWarning} tone={scan.critical_count + scan.high_count ? "warning" : "success"} />
        <StatCard label="Coverage" value={percent(scan.coverage_percent)} hint={`${scan.checked_dependencies} checked`} icon={FileCheck2} tone={scan.unknown_dependencies ? "warning" : "success"} />
        <StatCard label="Duration" value={formatDuration(scan.duration_seconds)} hint={formatDate(scan.completed_at)} icon={Timer} tone="default" />
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="w-full justify-start overflow-x-auto sm:w-auto">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="dependencies">Dependencies <span className="ml-1 font-mono text-[10px] text-slate-600">{scan.total_dependencies}</span></TabsTrigger>
          <TabsTrigger value="vulnerabilities">Vulnerabilities <span className="ml-1 font-mono text-[10px] text-slate-600">{scan.vulnerability_count}</span></TabsTrigger>
          <TabsTrigger value="remediation">Remediation</TabsTrigger>
          <TabsTrigger value="reports">Reports & SBOM</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <Overview scan={scan} />
        </TabsContent>
        <TabsContent value="dependencies">
          {scan.status === "completed" ? (
            <DependencyExplorer scan={scan} />
          ) : (
            <div className="panel p-8 text-center text-sm text-muted">Dependencies become interactive after the scan completes.</div>
          )}
        </TabsContent>
        <TabsContent value="vulnerabilities">
          {scan.status === "completed" ? (
            <VulnerabilityExplorer scan={scan} />
          ) : (
            <div className="panel p-8 text-center text-sm text-muted">Advisories become interactive after the scan completes.</div>
          )}
        </TabsContent>
        <TabsContent value="remediation">
          <RemediationPanel scanId={scan.id} enabled={scan.status === "completed"} />
        </TabsContent>
        <TabsContent value="reports">
          <ReportsPanel scan={scan} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Overview({ scan }: { scan: ScanDetail }) {
  const breakdown = (scan.score_breakdown ?? {}) as Record<string, unknown>;
  const metadata = [
    ["Source type", scan.source_type],
    ["Source", scan.source_reference ?? "—"],
    ["Created", formatDate(scan.created_at)],
    ["Started", formatDate(scan.started_at)],
    ["Completed", formatDate(scan.completed_at)],
    ["Duration", formatDuration(scan.duration_seconds)],
    ["Ecosystems", scan.ecosystems.join(", ") || "—"],
    ["SBOM serial", scan.sbom_serial ? `${scan.sbom_serial.slice(0, 18)}…` : "—"],
  ];
  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-12">
        <Card className="xl:col-span-4">
          <CardHeader>
            <div>
              <CardTitle>Security score</CardTitle>
              <CardDescription>Exposure-driven confidence score.</CardDescription>
            </div>
            <GradeBadge score={scan.security_score} grade={scan.score_grade} />
          </CardHeader>
          <CardContent>
            <ScoreGauge score={scan.security_score} grade={scan.score_grade} />
            <div className="mt-2 grid grid-cols-3 gap-2 border-t border-border/70 pt-3 text-center">
              <Metric label="Vuln penalty" value={String(breakdown.vulnerability_penalty ?? "—")} />
              <Metric label="Health penalty" value={String(breakdown.health_penalty ?? "—")} />
              <Metric label="Confidence" value={String(breakdown.coverage_multiplier ?? "—")} />
            </div>
            <p className="mt-3 text-[10px] leading-relaxed text-slate-600">
              Dependency Watcher priority is a proprietary heuristic. It is not an official CVSS score.
            </p>
          </CardContent>
        </Card>

        <Card className="xl:col-span-4">
          <CardHeader>
            <div>
              <CardTitle>Severity distribution</CardTitle>
              <CardDescription>Matched OSV advisories by severity.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <SeverityDonut scan={scan} />
          </CardContent>
        </Card>

        <Card className="xl:col-span-4">
          <CardHeader>
            <div>
              <CardTitle>Component health</CardTitle>
              <CardDescription>Explicit certainty and maintenance signals.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-2.5">
            <HealthRow icon={FileCheck2} label="Checked by OSV" value={`${scan.checked_dependencies}/${scan.total_dependencies}`} tone="text-emerald-300" />
            <HealthRow icon={AlertTriangle} label="Unverified" value={scan.unknown_dependencies} tone={scan.unknown_dependencies ? "text-amber-300" : "text-slate-400"} />
            <HealthRow icon={PackageOpen} label="Outdated" value={scan.outdated_count} tone={scan.outdated_count ? "text-amber-300" : "text-slate-400"} />
            <HealthRow icon={ShieldAlert} label="Deprecated" value={scan.deprecated_count} tone={scan.deprecated_count ? "text-orange-300" : "text-slate-400"} />
            <HealthRow icon={Fingerprint} label="Unpinned" value={scan.unpinned_count} tone={scan.unpinned_count ? "text-sky-300" : "text-slate-400"} />
            <HealthRow icon={Wrench} label="Direct components" value={scan.direct_dependencies} tone="text-slate-400" />
            <div className="pt-2">
              <div className="mb-1.5 flex justify-between text-[10px] text-slate-600">
                <span>Inspection confidence</span>
                <span className="font-mono">{percent(scan.coverage_percent)}</span>
              </div>
              <Progress value={scan.coverage_percent ?? 0} className="h-1" />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        <Card className="xl:col-span-7">
          <CardHeader>
            <div>
              <CardTitle>Scan context</CardTitle>
              <CardDescription>Provenance and analysis metadata.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
              {metadata.map(([label, value]) => (
                <div key={label} className="min-w-0 border-b border-border/50 pb-2">
                  <dt className="text-[9px] uppercase tracking-wider text-slate-600">{label}</dt>
                  <dd className="mt-1 truncate text-xs text-slate-300" title={value}>{value}</dd>
                </div>
              ))}
            </dl>
            {scan.dependency_files.length > 0 && (
              <div className="mt-4">
                <p className="eyebrow mb-2">Manifests</p>
                <div className="flex flex-wrap gap-1.5">
                  {scan.dependency_files.map((file) => (
                    <span key={file} className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{file}</span>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4 xl:col-span-5">
          <Card>
            <CardHeader>
              <div>
                <CardTitle className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  Evidence sources
                </CardTitle>
                <CardDescription>Sources queried for this scan.</CardDescription>
              </div>
            </CardHeader>
            <CardContent>
              {scan.sources_used.length ? (
                <ul className="space-y-1.5">
                  {scan.sources_used.map((source) => (
                    <li key={source} className="flex items-center gap-2 text-xs text-slate-400">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/60" />
                      {source}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-600">No external source was recorded.</p>
              )}
            </CardContent>
          </Card>

          {(scan.warnings.length > 0 || scan.errors.length > 0) && (
            <Card className="border-amber-500/15">
              <CardHeader>
                <div>
                  <CardTitle>Warnings & errors</CardTitle>
                  <CardDescription>Partial failures are surfaced, not hidden.</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {scan.errors.map((message) => (
                  <div key={message} className="rounded-md border border-red-500/15 bg-red-500/[0.05] p-2.5 text-[11px] leading-relaxed text-red-200/80">
                    {message}
                  </div>
                ))}
                {scan.warnings.map((message) => (
                  <div key={message} className="rounded-md border border-amber-500/15 bg-amber-500/[0.04] p-2.5 text-[11px] leading-relaxed text-amber-200/75">
                    {message}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[9px] uppercase tracking-wider text-slate-600">{label}</div>
      <div className="mt-0.5 font-mono text-xs text-slate-300">{value}</div>
    </div>
  );
}

function HealthRow({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof FileCheck2;
  label: string;
  value: string | number;
  tone: string;
}) {
  return (
    <div className="flex items-center gap-2.5">
      <Icon className="h-3.5 w-3.5 text-slate-600" />
      <span className="text-xs text-slate-400">{label}</span>
      <span className={`ml-auto font-mono text-xs ${tone}`}>{value}</span>
    </div>
  );
}
