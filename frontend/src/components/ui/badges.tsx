import type { InspectionStatus, ScanStatus, Severity } from "@/types";
import { cn } from "@/lib/utils";

const severityStyles: Record<Severity, string> = {
  CRITICAL: "border-red-500/35 bg-red-500/12 text-red-300",
  HIGH: "border-orange-500/35 bg-orange-500/12 text-orange-300",
  MEDIUM: "border-amber-500/35 bg-amber-500/10 text-amber-300",
  LOW: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  INFO: "border-slate-500/30 bg-slate-500/10 text-slate-300",
  UNKNOWN: "border-slate-600/40 bg-slate-700/20 text-slate-400",
};

export const severityHex: Record<Severity, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#f59e0b",
  LOW: "#38bdf8",
  INFO: "#64748b",
  UNKNOWN: "#475569",
};

export function SeverityBadge({
  severity,
  dot = false,
  className,
}: {
  severity?: Severity | null;
  dot?: boolean;
  className?: string;
}) {
  const value = severity ?? "UNKNOWN";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
        severityStyles[value],
        className,
      )}
    >
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
      {value}
    </span>
  );
}

export function InspectionBadge({ status }: { status: InspectionStatus }) {
  const styles: Record<InspectionStatus, string> = {
    VULNERABLE: "border-red-500/30 bg-red-500/10 text-red-300",
    CHECKED: "border-emerald-500/25 bg-emerald-500/8 text-emerald-300",
    UNKNOWN: "border-slate-600/40 bg-slate-700/20 text-slate-400",
    ERROR: "border-rose-500/25 bg-rose-500/10 text-rose-300",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-semibold tracking-wide",
        styles[status],
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {status === "CHECKED" ? "SAFE" : status}
    </span>
  );
}

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const styles: Record<ScanStatus, string> = {
    pending: "border-slate-500/30 bg-slate-500/10 text-slate-300",
    running: "border-blue-500/30 bg-blue-500/10 text-blue-300",
    completed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    failed: "border-red-500/30 bg-red-500/10 text-red-300",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
        styles[status],
      )}
    >
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full bg-current",
          (status === "running" || status === "pending") && "animate-pulse",
        )}
      />
      {status}
    </span>
  );
}

export function GradeBadge({ score, grade }: { score?: number | null; grade?: string | null }) {
  const tone =
    score == null
      ? "border-slate-600/40 bg-slate-700/20 text-slate-400"
      : score >= 80
        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
        : score >= 60
          ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
          : "border-red-500/30 bg-red-500/10 text-red-300";
  return (
    <span className={cn("inline-flex h-8 min-w-8 items-center justify-center rounded-md border px-2 font-mono text-sm font-bold", tone)}>
      {grade ?? "–"}
    </span>
  );
}

export function RiskFlags({ flags, deprecated }: { flags: string[]; deprecated?: boolean }) {
  const normalized = [...new Set(flags)];
  if (deprecated && !normalized.includes("deprecated")) normalized.unshift("deprecated");
  if (!normalized.length) return <span className="text-xs text-slate-600">—</span>;
  return (
    <div className="flex max-w-[220px] flex-wrap gap-1">
      {normalized.slice(0, 3).map((flag) => (
        <span
          key={flag}
          className="rounded border border-border bg-surface px-1.5 py-0.5 text-[10px] text-slate-400"
        >
          {flag.replaceAll("_", " ")}
        </span>
      ))}
      {normalized.length > 3 && (
        <span className="px-1 text-[10px] text-slate-500">+{normalized.length - 3}</span>
      )}
    </div>
  );
}
