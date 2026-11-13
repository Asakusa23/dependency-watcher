import { useState } from "react";
import { Boxes, ChevronDown, Plus, Radar } from "lucide-react";
import { useScans } from "@/context/ScanContext";
import { PageHeader, EmptyState, ErrorState, LoadingBlock, Skeleton } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/form";
import { DependencyExplorer } from "@/components/dependencies/DependencyExplorer";
import { NewScanDialog } from "@/components/scans/NewScanDialog";
import { ScanStatusBadge } from "@/components/ui/badges";
import { formatDate } from "@/lib/format";

export function DependenciesPage() {
  const { scans, activeScan, activeScanId, setActiveScanId, loading, error, refresh } = useScans();
  const [newOpen, setNewOpen] = useState(false);
  const completed = scans.filter((scan) => scan.status === "completed");

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Inventory"
        title="Dependency explorer"
        description="Inspect exact versions, freshness, license, advisory exposure and inspection status for every discovered component."
        actions={
          <>
            {completed.length > 0 && (
              <div className="relative hidden sm:block">
                <Select
                  value={activeScanId ?? ""}
                  onChange={(event) => setActiveScanId(event.target.value)}
                  className="h-9 max-w-[280px] text-xs"
                  aria-label="Select scan"
                >
                  {completed.map((scan) => (
                    <option key={scan.id} value={scan.id}>
                      {scan.project_name} · {formatDate(scan.completed_at, false)}
                    </option>
                  ))}
                </Select>
                <ChevronDown className="pointer-events-none absolute right-3 top-2.5 h-4 w-4 text-slate-500" />
              </div>
            )}
            <Button size="sm" onClick={() => setNewOpen(true)}>
              <Plus className="h-4 w-4" />
              New scan
            </Button>
          </>
        }
      />

      {loading && !scans.length ? (
        <div className="space-y-4">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-[400px] w-full" />
        </div>
      ) : error && !scans.length ? (
        <ErrorState message={error} onRetry={() => void refresh()} />
      ) : !activeScan ? (
        <div className="panel">
          <EmptyState
            icon={Boxes}
            title="No component inventory"
            description="Complete a scan to explore dependencies, latest versions and vulnerability evidence."
            action={
              <Button size="sm" onClick={() => setNewOpen(true)}>
                <Radar className="h-4 w-4" />
                Start a scan
              </Button>
            }
          />
        </div>
      ) : activeScan.status !== "completed" ? (
        <div className="panel p-8 text-center">
          <ScanStatusBadge status={activeScan.status} />
          <p className="mt-3 text-sm text-slate-300">{activeScan.project_name} is still being analyzed.</p>
          <p className="mt-1 text-xs text-muted">
            This view updates when the scan completes. Current phase: {activeScan.phase}.
          </p>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-1 text-[11px] text-slate-500">
            <span>
              Active project: <span className="text-slate-300">{activeScan.project_name}</span>
            </span>
            <span className="text-slate-700">·</span>
            <span>{activeScan.ecosystems.join(" / ")}</span>
            <span className="text-slate-700">·</span>
            <span>{activeScan.total_dependencies} components</span>
            <span className="text-slate-700">·</span>
            <span>{activeScan.direct_dependencies} direct</span>
          </div>
          <DependencyExplorer scan={activeScan} />
        </>
      )}

      <NewScanDialog open={newOpen} onOpenChange={setNewOpen} />
    </div>
  );
}
