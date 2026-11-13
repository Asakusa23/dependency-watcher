import { useMemo, useState } from "react";
import { FilterX, Search, ShieldAlert } from "lucide-react";
import { DependencyTable } from "@/components/dependencies/DependencyTable";
import { DependencyDialog } from "@/components/dependencies/DependencyDialog";
import { VulnerabilityDialog } from "@/components/vulnerabilities/VulnerabilityDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/form";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { useDependencies } from "@/hooks/useApiData";
import { cn } from "@/lib/utils";
import type { ScanSummary } from "@/types";

const emptyFilters = {
  search: "",
  ecosystem: "",
  severity: "",
  direct: undefined as boolean | undefined,
  outdated: undefined as boolean | undefined,
  vulnerableOnly: false,
};

export function DependencyExplorer({ scan }: { scan: ScanSummary }) {
  const [filters, setFilters] = useState(emptyFilters);
  const search = useDebouncedValue(filters.search, 250);
  const [selectedDependency, setSelectedDependency] = useState<number | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<number | null>(null);
  const [depOpen, setDepOpen] = useState(false);
  const [vulnOpen, setVulnOpen] = useState(false);

  const queryFilters = useMemo(
    () => ({ ...filters, search }),
    [filters, search],
  );
  const resource = useDependencies(scan.id, queryFilters);
  const active = Object.entries(filters).some(([key, value]) => {
    if (key === "direct" || key === "outdated") return value !== undefined;
    if (key === "vulnerableOnly") return value;
    return Boolean(value);
  });

  return (
    <div className="space-y-3">
      <div className="panel flex flex-col gap-3 p-3 lg:flex-row lg:items-center">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-600" />
          <Input
            value={filters.search}
            onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))}
            placeholder="Search package name or purl…"
            className="h-9 pl-9 text-xs"
            aria-label="Search dependencies"
          />
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Select
            value={filters.ecosystem}
            onChange={(event) => setFilters((current) => ({ ...current, ecosystem: event.target.value }))}
            className="h-9 text-xs"
            aria-label="Filter ecosystem"
          >
            <option value="">All ecosystems</option>
            {scan.ecosystems.map((ecosystem) => (
              <option key={ecosystem} value={ecosystem}>{ecosystem}</option>
            ))}
          </Select>
          <Select
            value={filters.severity}
            onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}
            className="h-9 text-xs"
            aria-label="Filter severity"
          >
            <option value="">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </Select>
          <Select
            value={filters.direct === undefined ? "" : String(filters.direct)}
            onChange={(event) =>
              setFilters((current) => ({
                ...current,
                direct: event.target.value === "" ? undefined : event.target.value === "true",
              }))
            }
            className="h-9 text-xs"
            aria-label="Filter dependency type"
          >
            <option value="">Direct + transitive</option>
            <option value="true">Direct only</option>
            <option value="false">Transitive only</option>
          </Select>
          <Select
            value={filters.outdated === undefined ? "" : String(filters.outdated)}
            onChange={(event) =>
              setFilters((current) => ({
                ...current,
                outdated: event.target.value === "" ? undefined : event.target.value === "true",
              }))
            }
            className="h-9 text-xs"
            aria-label="Filter outdated"
          >
            <option value="">Any freshness</option>
            <option value="true">Outdated only</option>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setFilters((current) => ({ ...current, vulnerableOnly: !current.vulnerableOnly }))}
            className={cn(
              "inline-flex h-9 items-center gap-1.5 rounded-lg border px-3 text-xs font-medium transition-colors",
              filters.vulnerableOnly
                ? "border-red-500/35 bg-red-500/10 text-red-300"
                : "border-border bg-surface text-slate-400 hover:text-slate-200",
            )}
            aria-pressed={filters.vulnerableOnly}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            Vulnerable
          </button>
          {active && (
            <Button variant="ghost" size="sm" onClick={() => setFilters(emptyFilters)} title="Reset filters">
              <FilterX className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
      </div>

      <div className="flex items-center justify-between px-1 text-[11px] text-slate-500">
        <span>
          {resource.data ? (
            <>
              Showing <span className="text-slate-300">{resource.data.items.length}</span> of{" "}
              <span className="text-slate-300">{resource.data.total}</span> components
              {resource.data.total > resource.data.items.length && " (server limit reached)"}
            </>
          ) : (
            "Loading component inventory"
          )}
        </span>
        <span className="hidden sm:inline">Priority combines advisory impact, exploit availability and directness</span>
      </div>

      {resource.error ? (
        <ErrorState message={resource.error} onRetry={resource.reload} />
      ) : resource.loading && !resource.data ? (
        <LoadingBlock label="Loading dependencies" />
      ) : (
        <div className="panel overflow-hidden">
          <DependencyTable
            items={resource.data?.items ?? []}
            onSelect={(dependency) => {
              setSelectedDependency(dependency.id);
              setDepOpen(true);
            }}
          />
        </div>
      )}

      <DependencyDialog
        scanId={scan.id}
        dependencyId={selectedDependency}
        open={depOpen}
        onOpenChange={setDepOpen}
        onVulnerability={(id) => {
          setSelectedVulnerability(id);
          setVulnOpen(true);
        }}
      />
      <VulnerabilityDialog
        vulnerabilityId={selectedVulnerability}
        open={vulnOpen}
        onOpenChange={setVulnOpen}
      />
    </div>
  );
}
