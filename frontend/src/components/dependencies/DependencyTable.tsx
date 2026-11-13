import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, Boxes, ExternalLink } from "lucide-react";
import type { Dependency, Severity } from "@/types";
import { Badge } from "@/components/ui/badge";
import { InspectionBadge, RiskFlags, SeverityBadge } from "@/components/ui/badges";
import { EmptyState } from "@/components/ui/states";
import { cn } from "@/lib/utils";
import { titleCase } from "@/lib/format";

const severityRank: Record<Severity, number> = {
  CRITICAL: 6,
  HIGH: 5,
  MEDIUM: 4,
  LOW: 3,
  INFO: 2,
  UNKNOWN: 1,
};

const priorityStyles: Record<Severity, string> = {
  CRITICAL: "text-red-300",
  HIGH: "text-orange-300",
  MEDIUM: "text-amber-300",
  LOW: "text-sky-300",
  INFO: "text-slate-400",
  UNKNOWN: "text-slate-500",
};

type SortKey = "name" | "version" | "vulnerability_count" | "priority_score" | "latest_version";

function sortValue(dep: Dependency, key: SortKey): string | number {
  if (key === "vulnerability_count" || key === "priority_score") return dep[key];
  if (key === "latest_version") return dep.latest_version ?? "";
  return dep[key] ?? "";
}

export function DependencyTable({
  items,
  onSelect,
  emptyHint = "No dependencies match the current filters.",
}: {
  items: Dependency[];
  onSelect: (dependency: Dependency) => void;
  emptyHint?: string;
}) {
  const [sort, setSort] = useState<{ key: SortKey; direction: "asc" | "desc" }>({
    key: "priority_score",
    direction: "desc",
  });

  const sorted = useMemo(() => {
    return [...items].sort((a, b) => {
      const left = sortValue(a, sort.key);
      const right = sortValue(b, sort.key);
      const result =
        typeof left === "number" && typeof right === "number"
          ? left - right
          : String(left).localeCompare(String(right), undefined, { sensitivity: "base" });
      return sort.direction === "asc" ? result : -result;
    });
  }, [items, sort]);

  const toggleSort = (key: SortKey) => {
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
        : { key, direction: key === "name" ? "asc" : "desc" },
    );
  };

  if (!items.length) {
    return (
      <EmptyState
        icon={Boxes}
        title="No dependencies"
        description={emptyHint}
        className="py-12"
      />
    );
  }

  const Header = ({ label, sortKey, className }: { label: string; sortKey: SortKey; className?: string }) => (
    <th className={cn("px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500", className)}>
      <button className="inline-flex items-center gap-1 hover:text-slate-300" onClick={() => toggleSort(sortKey)}>
        {label}
        {sort.key === sortKey ? (
          sort.direction === "asc" ? (
            <ArrowUp className="h-3 w-3" />
          ) : (
            <ArrowDown className="h-3 w-3" />
          )
        ) : (
          <ArrowUpDown className="h-3 w-3 opacity-40" />
        )}
      </button>
    </th>
  );

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[980px] border-collapse text-sm">
        <thead className="border-b border-border bg-surface/60">
          <tr>
            <Header label="Package" sortKey="name" className="pl-5" />
            <Header label="Version" sortKey="version" />
            <Header label="Latest" sortKey="latest_version" />
            <Header label="Findings" sortKey="vulnerability_count" />
            <Header label="Priority" sortKey="priority_score" />
            <th className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
              License
            </th>
            <th className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
              Risk
            </th>
            <th className="px-3 py-2.5 pr-5 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
              Inspection
            </th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((dep) => (
            <tr
              key={dep.id}
              tabIndex={0}
              onClick={() => onSelect(dep)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(dep);
                }
              }}
              className="row-hover cursor-pointer focus:bg-white/[0.03] focus:outline-none"
            >
              <td className="py-3 pl-5 pr-3">
                <div className="flex items-center gap-2">
                  <span className="max-w-[220px] truncate font-medium text-slate-200">{dep.name}</span>
                  {dep.direct ? (
                    <Badge className="border-blue-500/20 bg-blue-500/10 text-blue-300">direct</Badge>
                  ) : (
                    <span className="text-[10px] text-slate-600">transitive</span>
                  )}
                </div>
                <div className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-500">
                  <span>{dep.ecosystem}</span>
                  <span className="text-slate-700">·</span>
                  <span className="truncate">{dep.purl ?? "no purl"}</span>
                </div>
              </td>
              <td className="px-3 py-3">
                <div className="font-mono text-xs text-slate-300">{dep.version || "unpinned"}</div>
                <div className="mt-0.5 max-w-[140px] truncate font-mono text-[10px] text-slate-600">
                  {dep.version_specifier || (dep.pinned ? "pinned" : "unresolved")}
                </div>
              </td>
              <td className="px-3 py-3">
                {dep.latest_version ? (
                  <div className="flex items-center gap-1.5">
                    <span className={cn("font-mono text-xs", dep.outdated ? "text-amber-300" : "text-slate-400")}>
                      {dep.latest_version}
                    </span>
                    {dep.outdated && <span className="text-[9px] uppercase text-amber-500">update</span>}
                  </div>
                ) : (
                  <span className="text-xs text-slate-600">—</span>
                )}
              </td>
              <td className="px-3 py-3">
                {dep.vulnerability_count > 0 ? (
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-slate-200">{dep.vulnerability_count}</span>
                    <SeverityBadge severity={dep.max_severity} />
                  </div>
                ) : (
                  <span className="text-xs text-slate-600">0</span>
                )}
              </td>
              <td className="px-3 py-3">
                <div className={cn("text-[10px] font-semibold uppercase tracking-wide", priorityStyles[dep.priority_level])}>
                  {dep.priority_level}
                </div>
                <div className="mt-0.5 font-mono text-[10px] text-slate-600">{Math.round(dep.priority_score)}</div>
              </td>
              <td className="px-3 py-3">
                <span className="max-w-[120px] truncate text-xs text-slate-400" title={dep.license ?? undefined}>
                  {dep.license ?? "—"}
                </span>
              </td>
              <td className="px-3 py-3">
                <RiskFlags flags={dep.risk_flags} deprecated={dep.deprecated} />
              </td>
              <td className="px-3 py-3 pr-5">
                <div className="space-y-1">
                  <InspectionBadge status={dep.inspection_status} />
                  {dep.health_status && dep.health_status !== "checked" && (
                    <div className="text-[9px] text-slate-600">{titleCase(dep.health_status)}</div>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex items-center justify-between border-t border-border bg-surface/40 px-5 py-2 text-[10px] text-slate-600">
        <span>
          {items.length} {items.length === 1 ? "component" : "components"}
        </span>
        <span className="inline-flex items-center gap-1">
          Select a row for evidence
          <ExternalLink className="h-2.5 w-2.5" />
        </span>
      </div>
    </div>
  );
}
