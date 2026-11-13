import { AlertOctagon, ArrowRight, CheckCircle2, LoaderCircle, PackageOpen, Wrench } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/ui/badges";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { api } from "@/lib/api";
import { useApiResource } from "@/hooks/useApiResource";
import type { Remediation } from "@/types";
import { cn } from "@/lib/utils";

export function RemediationPanel({ scanId, enabled = true }: { scanId: string; enabled?: boolean }) {
  const resource = useApiResource<Remediation>(() => api.remediation(scanId), scanId, { enabled });

  if (!enabled) {
    return <div className="panel p-6 text-sm text-muted">Remediation is available when the scan completes.</div>;
  }
  if (resource.error) return <ErrorState message={resource.error} onRetry={resource.reload} />;
  if (resource.loading && !resource.data) return <LoadingBlock label="Building remediation plan" />;
  if (!resource.data) return null;

  const data = resource.data;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Summary label="Urgent upgrades" value={data.summary.urgent_upgrades} tone="danger" />
        <Summary label="Recommendations" value={data.summary.total_recommendations} tone="accent" />
        <Summary label="No published fix" value={data.summary.unfixable} tone="warning" />
        <Summary label="Maintenance updates" value={data.summary.maintenance_updates} tone="default" />
      </div>

      {data.recommendations.length === 0 ? (
        <div className="panel flex flex-col items-center justify-center px-6 py-12 text-center">
          <CheckCircle2 className="h-7 w-7 text-emerald-400" />
          <p className="mt-3 text-sm font-medium text-slate-200">No advisory-driven upgrades</p>
          <p className="mt-1 max-w-lg text-xs leading-relaxed text-muted">
            No known advisory fixes were identified for checked components. Review maintenance updates and
            unknown components before treating the project as clear.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {data.recommendations.map((item) => (
            <div key={item.dependency_id} className="panel p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={item.severity} dot />
                    <span className="text-sm font-medium text-slate-200">{item.package}</span>
                    <span className="text-[10px] text-slate-600">{item.ecosystem}</span>
                    {!item.direct && <Badge>transitive</Badge>}
                    {item.breaking_risk === "major" && (
                      <Badge className="border-orange-500/25 bg-orange-500/[0.08] text-orange-300">major risk</Badge>
                    )}
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-2 font-mono text-xs">
                    <span className="text-slate-500">{item.current_version || "unpinned"}</span>
                    <ArrowRight className="h-3 w-3 text-slate-600" />
                    <span className={item.recommended_version ? "text-emerald-300" : "text-amber-400"}>
                      {item.recommended_version || "manual review"}
                    </span>
                  </div>
                  <ul className="mt-2 space-y-1">
                    {item.reasons.map((reason) => (
                      <li key={reason} className="text-[11px] leading-relaxed text-slate-500">• {reason}</li>
                    ))}
                  </ul>
                  {item.conflicts.length > 0 && (
                    <div className="mt-2 rounded-md border border-amber-500/15 bg-amber-500/[0.04] p-2">
                      {item.conflicts.map((conflict) => (
                        <div key={conflict} className="flex items-start gap-1.5 py-0.5 text-[10px] leading-relaxed text-amber-200/75">
                          <AlertOctagon className="mt-0.5 h-3 w-3 shrink-0" />
                          {conflict}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Badge className={cn("font-mono", item.priority_level === "CRITICAL" && "border-red-500/25 text-red-300")}>
                    P{item.priority_score}
                  </Badge>
                  <Badge>{item.action.replace("_", " ")}</Badge>
                </div>
              </div>
              {item.advisories.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1 border-t border-border/60 pt-2">
                  {item.advisories.slice(0, 8).map((advisory) => (
                    <span key={advisory} className="font-mono text-[9px] text-slate-600">{advisory}</span>
                  ))}
                  {item.advisories.length > 8 && <span className="text-[9px] text-slate-700">+{item.advisories.length - 8}</span>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {data.maintenance_updates.length > 0 && (
        <Card>
          <CardHeader>
            <div>
              <CardTitle className="flex items-center gap-2">
                <Wrench className="h-4 w-4 text-slate-400" />
                Maintenance updates
              </CardTitle>
              <CardDescription>Outdated packages without a matched advisory. Optional hygiene, not an emergency.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-1">
            {data.maintenance_updates.map((item) => (
              <div key={item.dependency_id} className="flex flex-wrap items-center gap-2 rounded-md border border-border/60 bg-surface/50 px-3 py-2 text-xs">
                <PackageOpen className="h-3.5 w-3.5 text-slate-600" />
                <span className="text-slate-300">{item.package}</span>
                <span className="font-mono text-[10px] text-slate-600">{item.ecosystem}</span>
                <span className="ml-auto font-mono text-[10px] text-slate-500">{item.current_version}</span>
                <ArrowRight className="h-3 w-3 text-slate-700" />
                <span className="font-mono text-[10px] text-amber-300">{item.latest_version}</span>
                {item.breaking_risk === "major" && <Badge className="text-[9px]">major</Badge>}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <p className="text-[11px] leading-relaxed text-slate-600">
        {data.notice}
      </p>
    </div>
  );
}

function Summary({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "danger" | "warning" | "accent" | "default";
}) {
  const tones = {
    danger: "text-red-300 border-red-500/15 bg-red-500/[0.05]",
    warning: "text-amber-300 border-amber-500/15 bg-amber-500/[0.05]",
    accent: "text-blue-300 border-blue-500/15 bg-blue-500/[0.05]",
    default: "text-slate-300 border-border bg-surface",
  };
  return (
    <div className={cn("rounded-lg border p-3", tones[tone])}>
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-1 font-mono text-xl">{value}</div>
    </div>
  );
}
