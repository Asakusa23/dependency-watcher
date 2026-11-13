import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ArrowDownRight,
  ArrowLeftRight,
  ArrowRight,
  ArrowUpRight,
  GitCompareArrows,
  Minus,
  Plus,
  RefreshCw,
} from "lucide-react";
import { useScans } from "@/context/ScanContext";
import { useApiResource } from "@/hooks/useApiResource";
import { api } from "@/lib/api";
import type { CompareResult, Vulnerability } from "@/types";
import { PageHeader, EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { GradeBadge, SeverityBadge, ScanStatusBadge } from "@/components/ui/badges";
import { Badge } from "@/components/ui/badge";
import { VulnerabilityTable } from "@/components/vulnerabilities/VulnerabilityTable";
import { VulnerabilityDialog } from "@/components/vulnerabilities/VulnerabilityDialog";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

export function ComparePage() {
  const { scans, loading } = useScans();
  const [params, setParams] = useSearchParams();
  const completed = useMemo(() => scans.filter((scan) => scan.status === "completed"), [scans]);
  const [a, setA] = useState(params.get("a") ?? "");
  const [b, setB] = useState(params.get("b") ?? "");
  const [selectedVulnerability, setSelectedVulnerability] = useState<number | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  useEffect(() => {
    if (!a && completed[0]) setA(completed[1]?.id ?? completed[0].id);
    if (!b && completed[0]) setB(completed[0].id);
  }, [a, b, completed]);

  useEffect(() => {
    if (a && b) {
      const next = new URLSearchParams(params);
      next.set("a", a);
      next.set("b", b);
      if (next.toString() !== params.toString()) setParams(next, { replace: true });
    }
  }, [a, b, params, setParams]);

  const comparison = useApiResource<CompareResult>(
    () => api.compare(a, b),
    `${a}:${b}`,
    { enabled: Boolean(a && b && a !== b) },
  );

  const openVulnerability = (vulnerability: Vulnerability) => {
    setSelectedVulnerability(vulnerability.id);
    setDialogOpen(true);
  };

  const swap = () => {
    setA(b);
    setB(a);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Delta analysis"
        title="Compare scans"
        description="Track posture movement between two snapshots: added and removed components, version changes, and new or resolved advisories."
      />

      {loading && !scans.length ? (
        <LoadingBlock label="Loading scan history" />
      ) : completed.length < 2 ? (
        <div className="panel">
          <EmptyState
            icon={GitCompareArrows}
            title="Two completed scans are required"
            description="Run scans for two versions of a project or scan the same project twice after dependency updates."
            action={
              <Button onClick={() => (window.location.href = "/scans")}>
                Go to scans
              </Button>
            }
          />
        </div>
      ) : (
        <>
          <div className="panel flex flex-col gap-3 p-4 lg:flex-row lg:items-end">
            <div className="min-w-0 flex-1">
              <label className="mb-1.5 block text-[10px] font-semibold uppercase tracking-wider text-slate-500" htmlFor="compare-a">
                Baseline
              </label>
              <Select id="compare-a" value={a} onChange={(event) => setA(event.target.value)} className="h-10">
                {completed.map((scan) => (
                  <option key={scan.id} value={scan.id} disabled={scan.id === b}>
                    {scan.project_name} · {formatDate(scan.completed_at, false)} · {scan.score_grade ?? "?"}
                  </option>
                ))}
              </Select>
            </div>
            <Button variant="secondary" size="icon" className="mb-0.5 self-center" onClick={swap} title="Swap scans">
              <ArrowLeftRight className="h-4 w-4" />
            </Button>
            <div className="min-w-0 flex-1">
              <label className="mb-1.5 block text-[10px] font-semibold uppercase tracking-wider text-slate-500" htmlFor="compare-b">
                Current
              </label>
              <Select id="compare-b" value={b} onChange={(event) => setB(event.target.value)} className="h-10">
                {completed.map((scan) => (
                  <option key={scan.id} value={scan.id} disabled={scan.id === a}>
                    {scan.project_name} · {formatDate(scan.completed_at, false)} · {scan.score_grade ?? "?"}
                  </option>
                ))}
              </Select>
            </div>
            <Button variant="secondary" className="mb-0.5" onClick={comparison.reload} disabled={!a || !b || a === b || comparison.loading}>
              <RefreshCw className={cn("h-4 w-4", comparison.loading && "animate-spin")} />
              Compare
            </Button>
          </div>

          {a === b && (
            <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.05] px-4 py-3 text-xs text-amber-200/80">
              Select two different scans to compute a delta.
            </div>
          )}

          {comparison.error && <ErrorState message={comparison.error} onRetry={comparison.reload} />}
          {comparison.loading && !comparison.data && <LoadingBlock label="Comparing evidence" />}

          {comparison.data && a !== b && (
            <CompareResultView
              result={comparison.data}
              onVulnerability={openVulnerability}
            />
          )}
        </>
      )}

      <VulnerabilityDialog vulnerabilityId={selectedVulnerability} open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  );
}

function CompareResultView({
  result,
  onVulnerability,
}: {
  result: CompareResult;
  onVulnerability: (vulnerability: Vulnerability) => void;
}) {
  const { scan_a: left, scan_b: right, delta } = result;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <ScanSnapshot scan={left} label="Baseline" />
        <ScanSnapshot scan={right} label="Current" />
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <DeltaCard
          label="Security score"
          value={delta.security_score}
          suffix=" pts"
          goodWhenPositive
          baseline={left.security_score}
          current={right.security_score}
        />
        <DeltaCard
          label="Vulnerabilities"
          value={delta.vulnerabilities}
          goodWhenPositive={false}
          baseline={left.vulnerability_count}
          current={right.vulnerability_count}
        />
        <DeltaCard
          label="Critical findings"
          value={delta.critical}
          goodWhenPositive={false}
          baseline={left.critical_count}
          current={right.critical_count}
        />
        <DeltaCard
          label="Dependencies"
          value={delta.dependencies}
          goodWhenPositive={false}
          baseline={left.total_dependencies}
          current={right.total_dependencies}
        />
      </div>

      <Tabs defaultValue="changes">
        <TabsList>
          <TabsTrigger value="changes">
            Dependency changes
            <span className="ml-1.5 font-mono text-[10px] text-slate-600">
              {result.dependencies.added.length + result.dependencies.removed.length + result.dependencies.version_changed.length}
            </span>
          </TabsTrigger>
          <TabsTrigger value="new">
            New findings
            <span className="ml-1.5 font-mono text-[10px] text-red-400/70">{result.vulnerabilities.new.length}</span>
          </TabsTrigger>
          <TabsTrigger value="resolved">
            Resolved
            <span className="ml-1.5 font-mono text-[10px] text-emerald-400/70">{result.vulnerabilities.resolved.length}</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="changes">
          <div className="space-y-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <ChangeGroup title="Added components" icon={Plus} tone="text-emerald-300" count={result.dependencies.added.length}>
                {result.dependencies.added.map((dep) => (
                  <div key={`${dep.ecosystem}:${dep.name}:${dep.version}`} className="flex items-center gap-2 border-b border-border/60 px-4 py-2.5 last:border-0">
                    <span className="min-w-0 flex-1 truncate text-xs text-slate-300">{dep.name}</span>
                    <span className="font-mono text-[10px] text-slate-500">{dep.version || "unpinned"}</span>
                    <Badge className="text-[9px]">{dep.ecosystem}</Badge>
                    <SeverityBadge severity={dep.max_severity} />
                  </div>
                ))}
              </ChangeGroup>
              <ChangeGroup title="Removed components" icon={Minus} tone="text-slate-300" count={result.dependencies.removed.length}>
                {result.dependencies.removed.map((dep) => (
                  <div key={`${dep.ecosystem}:${dep.name}:${dep.version}`} className="flex items-center gap-2 border-b border-border/60 px-4 py-2.5 last:border-0">
                    <span className="min-w-0 flex-1 truncate text-xs text-slate-300">{dep.name}</span>
                    <span className="font-mono text-[10px] text-slate-500">{dep.version || "unpinned"}</span>
                    <Badge className="text-[9px]">{dep.ecosystem}</Badge>
                    <SeverityBadge severity={dep.max_severity} />
                  </div>
                ))}
              </ChangeGroup>
            </div>

            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Version changes</CardTitle>
                  <CardDescription>
                    {result.dependencies.version_changed.length} changed · {result.dependencies.unchanged_count} identical component versions
                  </CardDescription>
                </div>
              </CardHeader>
              <CardContent className="space-y-1.5">
                {result.dependencies.version_changed.length ? (
                  result.dependencies.version_changed.map((change) => (
                    <div key={`${change.ecosystem}:${change.name}`} className="flex flex-wrap items-center gap-2 rounded-md border border-border/60 bg-surface/50 px-3 py-2 text-xs">
                      <span className="font-medium text-slate-300">{change.name}</span>
                      <Badge className="text-[9px]">{change.ecosystem}</Badge>
                      <span className="ml-auto font-mono text-[10px] text-slate-500">{change.old_versions.join(", ")}</span>
                      <ArrowRight className="h-3 w-3 text-slate-700" />
                      <span className="font-mono text-[10px] text-blue-300">{change.new_versions.join(", ")}</span>
                    </div>
                  ))
                ) : (
                  <p className="py-4 text-center text-xs text-slate-600">No package versions changed.</p>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="new">
          <div className="panel overflow-hidden">
            <VulnerabilityTable
              items={result.vulnerabilities.new}
              onSelect={onVulnerability}
              emptyHint="No new advisories appeared between these snapshots."
            />
          </div>
        </TabsContent>
        <TabsContent value="resolved">
          <div className="panel overflow-hidden">
            <VulnerabilityTable
              items={result.vulnerabilities.resolved}
              onSelect={onVulnerability}
              emptyHint="No advisories were resolved between these snapshots."
            />
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ScanSnapshot({ scan, label }: { scan: CompareResult["scan_a"]; label: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4">
        <GradeBadge score={scan.security_score} grade={scan.score_grade} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-600">{label}</span>
            <ScanStatusBadge status={scan.status} />
          </div>
          <div className="mt-1 truncate text-sm font-medium text-slate-200">{scan.project_name}</div>
          <div className="mt-0.5 text-[10px] text-slate-600">
            {formatDate(scan.completed_at)} · {scan.total_dependencies} components · {scan.vulnerability_count} findings
          </div>
        </div>
        <div className="text-right">
          <div className="font-mono text-2xl font-semibold text-slate-200">{scan.security_score?.toFixed(0) ?? "—"}</div>
          <div className="text-[9px] uppercase tracking-wider text-slate-600">score</div>
        </div>
      </CardContent>
    </Card>
  );
}

function DeltaCard({
  label,
  value,
  suffix = "",
  goodWhenPositive,
  baseline,
  current,
}: {
  label: string;
  value: number | null;
  suffix?: string;
  goodWhenPositive: boolean;
  baseline: number | null;
  current: number | null;
}) {
  const isNeutral = value == null || value === 0;
  const good = value != null && (goodWhenPositive ? value > 0 : value < 0);
  const valueText =
    value == null
      ? "—"
      : `${value > 0 ? "+" : ""}${Number.isInteger(value) ? value : value.toFixed(1)}${suffix}`;
  return (
    <div className="panel p-4">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-2 flex items-center gap-2">
        <span
          className={cn(
            "font-mono text-xl font-semibold",
            isNeutral ? "text-slate-400" : good ? "text-emerald-300" : "text-red-300",
          )}
        >
          {valueText}
        </span>
        {!isNeutral &&
          (value! > 0 ? (
            <ArrowUpRight className={cn("h-4 w-4", good ? "text-emerald-400" : "text-red-400")} />
          ) : (
            <ArrowDownRight className={cn("h-4 w-4", good ? "text-emerald-400" : "text-red-400")} />
          ))}
      </div>
      <div className="mt-1 font-mono text-[10px] text-slate-600">
        {baseline ?? "—"} → {current ?? "—"}
      </div>
    </div>
  );
}

function ChangeGroup({
  title,
  icon: Icon,
  tone,
  count,
  children,
}: {
  title: string;
  icon: typeof Plus;
  tone: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle className={cn("flex items-center gap-2", tone)}>
            <Icon className="h-4 w-4" />
            {title}
          </CardTitle>
          <CardDescription>{count} package{count === 1 ? "" : "s"}</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {count ? children : <p className="px-4 py-6 text-center text-xs text-slate-600">None.</p>}
      </CardContent>
    </Card>
  );
}
