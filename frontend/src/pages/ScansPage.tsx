import { useMemo, useState } from "react";
import { Filter, Plus, Radar, RefreshCw, Search } from "lucide-react";
import { api } from "@/lib/api";
import { useScans } from "@/context/ScanContext";
import { PageHeader, EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScanTable } from "@/components/scans/ScanTable";
import { NewScanDialog } from "@/components/scans/NewScanDialog";
import { cn } from "@/lib/utils";

const filters = [
  { id: "all", label: "All" },
  { id: "completed", label: "Completed" },
  { id: "running", label: "Running" },
  { id: "failed", label: "Failed" },
] as const;

type FilterId = (typeof filters)[number]["id"];

export function ScansPage() {
  const { scans, loading, error, refresh, refreshing } = useScans();
  const [filter, setFilter] = useState<FilterId>("all");
  const [search, setSearch] = useState("");
  const [newOpen, setNewOpen] = useState(false);

  const filtered = useMemo(
    () =>
      scans.filter((scan) => {
        const matchesStatus =
          filter === "all" ||
          (filter === "running" ? scan.status === "running" || scan.status === "pending" : scan.status === filter);
        const matchesSearch =
          !search.trim() ||
          scan.project_name.toLowerCase().includes(search.trim().toLowerCase()) ||
          (scan.source_reference ?? "").toLowerCase().includes(search.trim().toLowerCase());
        return matchesStatus && matchesSearch;
      }),
    [scans, filter, search],
  );

  const counts = {
    all: scans.length,
    completed: scans.filter((scan) => scan.status === "completed").length,
    running: scans.filter((scan) => scan.status === "running" || scan.status === "pending").length,
    failed: scans.filter((scan) => scan.status === "failed").length,
  };

  const remove = async (id: string) => {
    await api.deleteScan(id);
    await refresh();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="History"
        title="Scans"
        description="Persistent scan history with local evidence. Running scans update automatically."
        actions={
          <>
            <Button variant="secondary" size="sm" onClick={() => void refresh()} disabled={refreshing}>
              <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setNewOpen(true)}>
              <Plus className="h-4 w-4" />
              New scan
            </Button>
          </>
        }
      />

      {error && <ErrorState message={error} onRetry={() => void refresh()} />}

      <div className="panel">
        <div className="flex flex-col gap-3 border-b border-border p-3 lg:flex-row lg:items-center">
          <div className="flex flex-wrap gap-1">
            {filters.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setFilter(item.id)}
                className={cn(
                  "inline-flex h-8 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors",
                  filter === item.id ? "bg-elevated text-slate-100" : "text-slate-500 hover:text-slate-300",
                )}
              >
                {item.label}
                <span className={cn("rounded px-1 font-mono text-[10px]", filter === item.id ? "bg-white/5 text-slate-400" : "text-slate-700")}>
                  {counts[item.id]}
                </span>
              </button>
            ))}
          </div>
          <div className="relative ml-auto w-full lg:max-w-xs">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-600" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Filter by project or source…"
              className="h-9 pl-9 text-xs"
              aria-label="Filter scans"
            />
          </div>
          <div className="hidden items-center gap-1 text-[10px] text-slate-600 sm:flex">
            <Filter className="h-3 w-3" />
            {filtered.length} shown
          </div>
        </div>

        {loading && !scans.length ? (
          <LoadingBlock label="Loading scan history" />
        ) : filtered.length ? (
          <ScanTable scans={filtered} onDelete={remove} />
        ) : scans.length ? (
          <EmptyState
            icon={Filter}
            title="No scans match"
            description="Adjust the status filter or search query to see stored scans."
            action={
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setFilter("all");
                  setSearch("");
                }}
              >
                Clear filters
              </Button>
            }
          />
        ) : (
          <EmptyState
            icon={Radar}
            title="No scans yet"
            description="Run your first scan against a local project, an uploaded ZIP, or a public GitHub repository."
            action={
              <Button size="sm" onClick={() => setNewOpen(true)}>
                <Plus className="h-4 w-4" />
                Start a scan
              </Button>
            }
          />
        )}
      </div>

      <NewScanDialog open={newOpen} onOpenChange={setNewOpen} />
    </div>
  );
}
