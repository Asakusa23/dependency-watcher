import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronRight, Clock3, LoaderCircle, Radar, Trash2 } from "lucide-react";
import type { ScanSummary } from "@/types";
import { GradeBadge, ScanStatusBadge } from "@/components/ui/badges";
import { formatDate, formatDuration, relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";

export function ScanTable({
  scans,
  onDelete,
  compact = false,
}: {
  scans: ScanSummary[];
  onDelete?: (id: string) => Promise<void>;
  compact?: boolean;
}) {
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState<string | null>(null);

  const remove = async (event: React.MouseEvent, id: string, name: string) => {
    event.stopPropagation();
    if (!onDelete) return;
    if (!window.confirm(`Delete the scan for “${name}”? Historical results will be removed.`)) return;
    setDeleting(id);
    try {
      await onDelete(id);
    } finally {
      setDeleting(null);
    }
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] border-collapse text-sm">
        <thead className="border-b border-border bg-surface/60">
          <tr>
            <th className="px-5 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Project</th>
            <th className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Status</th>
            <th className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Score</th>
            <th className="px-3 py-2.5 text-right text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Components</th>
            <th className="px-3 py-2.5 text-right text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Findings</th>
            <th className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Created</th>
            <th className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Duration</th>
            <th className="px-3 py-2.5 pr-5 text-right text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr
              key={scan.id}
              tabIndex={0}
              onClick={() => navigate(`/scans/${scan.id}`)}
              onKeyDown={(event) => {
                if (event.key === "Enter") navigate(`/scans/${scan.id}`);
              }}
              className="row-hover cursor-pointer focus:bg-white/[0.03] focus:outline-none"
            >
              <td className="max-w-[300px] py-3 pl-5 pr-3">
                <div className="flex items-center gap-2">
                  {scan.status === "running" || scan.status === "pending" ? (
                    <LoaderCircle className="h-3.5 w-3.5 animate-spin text-blue-400" />
                  ) : (
                    <Radar className={cn("h-3.5 w-3.5", scan.status === "failed" ? "text-red-400" : "text-slate-500")} />
                  )}
                  <span className="truncate font-medium text-slate-200">{scan.project_name}</span>
                </div>
                <div className="mt-0.5 flex items-center gap-1.5 pl-5 text-[10px] text-slate-600">
                  <span className="uppercase tracking-wide">{scan.source_type}</span>
                  <span>·</span>
                  <span className="truncate">{scan.ecosystems.join(", ") || "no components"}</span>
                </div>
              </td>
              <td className="px-3 py-3">
                <ScanStatusBadge status={scan.status} />
                {(scan.status === "running" || scan.status === "pending") && (
                  <div className="mt-1 w-24">
                    <div className="h-1 overflow-hidden rounded-full bg-slate-800">
                      <div className="h-full bg-blue-500" style={{ width: `${scan.progress}%` }} />
                    </div>
                  </div>
                )}
              </td>
              <td className="px-3 py-3">
                <div className="flex items-center gap-2">
                  <GradeBadge score={scan.security_score} grade={scan.score_grade} />
                  <span className="font-mono text-xs text-slate-400">
                    {scan.security_score != null ? scan.security_score.toFixed(0) : "—"}
                  </span>
                </div>
              </td>
              <td className="px-3 py-3 text-right font-mono text-xs text-slate-400">{scan.total_dependencies}</td>
              <td className="px-3 py-3 text-right">
                <div className="flex items-center justify-end gap-2">
                  {scan.critical_count + scan.high_count > 0 && (
                    <span className="rounded bg-red-500/10 px-1.5 py-0.5 font-mono text-[10px] text-red-300">
                      {scan.critical_count + scan.high_count} hot
                    </span>
                  )}
                  <span className="font-mono text-xs text-slate-300">{scan.vulnerability_count}</span>
                </div>
              </td>
              <td className="px-3 py-3">
                <div className="text-xs text-slate-400">{relativeTime(scan.created_at)}</div>
                {!compact && <div className="mt-0.5 text-[10px] text-slate-600">{formatDate(scan.created_at)}</div>}
              </td>
              <td className="px-3 py-3">
                <div className="flex items-center gap-1 text-xs text-slate-500">
                  <Clock3 className="h-3 w-3" />
                  {formatDuration(scan.duration_seconds)}
                </div>
              </td>
              <td className="px-3 py-3 pr-5 text-right">
                <div className="flex items-center justify-end gap-1">
                  {onDelete && (
                    <button
                      onClick={(event) => void remove(event, scan.id, scan.project_name)}
                      disabled={deleting === scan.id}
                      className="rounded-md p-1.5 text-slate-600 transition-colors hover:bg-red-500/10 hover:text-red-400 disabled:opacity-50"
                      aria-label={`Delete scan ${scan.project_name}`}
                    >
                      {deleting === scan.id ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                    </button>
                  )}
                  <ChevronRight className="h-4 w-4 text-slate-700" />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
