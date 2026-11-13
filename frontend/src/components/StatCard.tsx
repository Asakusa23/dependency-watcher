import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = "default",
  className,
}: {
  label: string;
  value: string | number;
  hint?: string;
  icon: LucideIcon;
  tone?: "default" | "danger" | "warning" | "success" | "accent";
  className?: string;
}) {
  const tones = {
    default: "text-slate-400 bg-slate-500/10 border-slate-500/20",
    danger: "text-red-400 bg-red-500/10 border-red-500/20",
    warning: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    success: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    accent: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  };
  return (
    <div className={cn("panel panel-hover p-4", className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted">{label}</p>
          <p className="mt-2 text-2xl font-semibold tracking-tight text-slate-100">{value}</p>
          {hint && <p className="mt-1 truncate text-[11px] text-slate-500">{hint}</p>}
        </div>
        <div className={cn("rounded-lg border p-2", tones[tone])}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
    </div>
  );
}
