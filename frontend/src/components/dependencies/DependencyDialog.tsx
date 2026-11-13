import { AlertTriangle, Boxes } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { InspectionBadge, RiskFlags, SeverityBadge } from "@/components/ui/badges";
import { ErrorState, Skeleton } from "@/components/ui/states";
import { useApiResource } from "@/hooks/useApiResource";
import { api } from "@/lib/api";
import { titleCase } from "@/lib/format";
import type { Dependency } from "@/types";

export function DependencyDialog({
  scanId,
  dependencyId,
  open,
  onOpenChange,
  onVulnerability,
}: {
  scanId: string;
  dependencyId: number | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onVulnerability: (id: number) => void;
}) {
  const resource = useApiResource<Dependency>(
    () => api.dependency(scanId, dependencyId as number),
    `${scanId}:${dependencyId}`,
    { enabled: open && dependencyId != null },
  );
  const dep = resource.data;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        {resource.loading && !dep ? (
          <div className="space-y-3">
            <Skeleton className="h-6 w-1/2" />
            <Skeleton className="h-24 w-full" />
          </div>
        ) : resource.error && !dep ? (
          <ErrorState message={resource.error} onRetry={resource.reload} />
        ) : dep ? (
          <>
            <div className="flex items-start gap-3 pr-8">
              <div className="rounded-lg border border-border bg-surface p-2 text-slate-400">
                <Boxes className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <DialogTitle className="break-words">{dep.name}</DialogTitle>
                <DialogDescription>
                  {dep.ecosystem} · {dep.version || "unpinned"} {dep.direct ? "· direct" : "· transitive"}
                </DialogDescription>
              </div>
            </div>

            <div className="mt-5 grid gap-2 sm:grid-cols-4">
              <Field label="Current" value={dep.version || "unpinned"} mono />
              <Field label="Latest" value={dep.latest_version || "—"} mono />
              <Field label="License" value={dep.license || "Unknown"} />
              <Field label="Scope" value={dep.scope || "runtime"} />
            </div>

            <div className="mt-4 rounded-lg border border-border bg-surface p-3">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={dep.max_severity} />
                <Badge className="font-mono">{dep.vulnerability_count} findings</Badge>
                <InspectionBadge status={dep.inspection_status} />
                <Badge>{dep.priority_level} priority · {Math.round(dep.priority_score)}</Badge>
              </div>
              <div className="mt-2 break-all font-mono text-[10px] text-slate-600">{dep.purl ?? "No package URL generated"}</div>
            </div>

            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <section>
                <p className="eyebrow mb-2">Declared in</p>
                <ul className="space-y-1 text-xs text-slate-400">
                  {dep.source_files.length ? dep.source_files.map((file) => <li key={file} className="font-mono text-[11px]">{file}</li>) : <li>—</li>}
                </ul>
                <p className="mt-3 text-[11px] text-slate-600">Specifier: <span className="font-mono">{dep.version_specifier || "none"}</span></p>
              </section>
              <section>
                <p className="eyebrow mb-2">Risk signals</p>
                <RiskFlags flags={dep.risk_flags} deprecated={dep.deprecated} />
                {dep.risk_reasons.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {dep.risk_reasons.slice(0, 5).map((reason) => (
                      <li key={reason} className="flex gap-1.5 text-[11px] leading-relaxed text-slate-500">
                        <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                        {reason}
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </div>

            {dep.inspection_status === "UNKNOWN" && dep.inspection_message && (
              <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/[0.05] p-3 text-[11px] leading-relaxed text-amber-200/80">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {dep.inspection_message}
              </div>
            )}
            {dep.inspection_status === "ERROR" && dep.inspection_message && (
              <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/[0.05] p-3 text-[11px] leading-relaxed text-red-200/80">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {dep.inspection_message}
              </div>
            )}

            <section className="mt-5">
              <div className="mb-2 flex items-center justify-between">
                <p className="eyebrow">Advisories</p>
                <span className="text-[10px] text-slate-600">{dep.health_status ? titleCase(dep.health_status) : ""}</span>
              </div>
              {dep.vulnerabilities?.length ? (
                <div className="space-y-1.5">
                  {dep.vulnerabilities.map((vuln) => (
                    <button
                      key={vuln.id}
                      type="button"
                      onClick={() => {
                        onOpenChange(false);
                        onVulnerability(vuln.id);
                      }}
                      className="flex w-full items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-left transition-colors hover:border-slate-500"
                    >
                      <SeverityBadge severity={vuln.severity} />
                      <span className="font-mono text-[11px] text-blue-300">{vuln.osv_id}</span>
                      <span className="min-w-0 flex-1 truncate text-[11px] text-slate-500">{vuln.summary}</span>
                      {vuln.cvss_score != null && <span className="font-mono text-[10px] text-slate-400">{vuln.cvss_score.toFixed(1)}</span>}
                    </button>
                  ))}
                </div>
              ) : (
                <p className="rounded-lg border border-border bg-surface p-3 text-xs text-slate-500">
                  No advisories stored for this component. Check the inspection status before treating it as
                  safe.
                </p>
              )}
            </section>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-surface p-2.5">
      <div className="text-[9px] uppercase tracking-wider text-slate-600">{label}</div>
      <div className={`mt-1 truncate text-xs text-slate-300 ${mono ? "font-mono" : ""}`} title={value}>{value}</div>
    </div>
  );
}
