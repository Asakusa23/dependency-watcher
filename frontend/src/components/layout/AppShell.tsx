import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Boxes,
  ChevronDown,
  GitCompareArrows,
  LayoutDashboard,
  Menu,
  Radar,
  Settings,
  ShieldCheck,
  WifiOff,
  X,
} from "lucide-react";
import { useScans } from "@/context/ScanContext";
import { useHealth } from "@/hooks/useApiData";
import { cn } from "@/lib/utils";
import { GradeBadge } from "@/components/ui/badges";

const navItems = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/scans", label: "Scans", icon: Radar },
  { to: "/dependencies", label: "Dependencies", icon: Boxes },
  { to: "/compare", label: "Compare", icon: GitCompareArrows },
  { to: "/settings", label: "Settings", icon: Settings },
];

const titles: Array<[RegExp, string]> = [
  [/^\/$/, "Dashboard"],
  [/^\/scans\/[^/]+$/, "Scan detail"],
  [/^\/scans$/, "Scan history"],
  [/^\/dependencies$/, "Dependency explorer"],
  [/^\/compare$/, "Scan comparison"],
  [/^\/settings$/, "Settings"],
];

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const { activeScan, scans, setActiveScanId } = useScans();
  const { health, online } = useHealth();
  const completed = scans.filter((scan) => scan.status === "completed");

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-16 items-center gap-3 border-b border-border/80 px-5">
        <div className="rounded-lg border border-blue-500/25 bg-blue-500/10 p-1.5 text-blue-400 shadow-glow">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-semibold tracking-tight text-white">Dependency Watcher</div>
          <div className="text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">
            Supply chain security
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-5" aria-label="Primary">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "border border-blue-500/15 bg-blue-500/10 text-blue-200"
                  : "border border-transparent text-slate-400 hover:bg-white/[0.035] hover:text-slate-200",
              )
            }
          >
            {({ isActive }) => (
              <>
                <item.icon className={cn("h-4 w-4", isActive ? "text-blue-400" : "text-slate-500 group-hover:text-slate-300")} />
                {item.label}
                {isActive && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-blue-400 shadow-[0_0_8px_rgba(96,165,250,.9)]" />}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {completed.length > 0 && (
        <div className="border-t border-border/80 px-3 py-3">
          <label htmlFor="sidebar-scan" className="eyebrow px-2">
            Active project
          </label>
          <div className="relative mt-2">
            <select
              id="sidebar-scan"
              value={activeScan?.id ?? ""}
              onChange={(event) => setActiveScanId(event.target.value)}
              className="select-dark h-9 w-full truncate pr-8 text-xs"
            >
              {completed.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.project_name} · {scan.score_grade ?? "?"} · {scan.security_score ?? "—"}
                </option>
              ))}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2.5 top-2.5 h-4 w-4 text-slate-500" />
          </div>
        </div>
      )}

      <div className="border-t border-border/80 px-5 py-4">
        <div className="flex items-center gap-2 text-[11px]">
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              online === false ? "bg-red-500" : online ? "bg-emerald-400" : "bg-slate-500 animate-pulse",
            )}
          />
          <span className="text-slate-400">
            {online === false ? "API unavailable" : online ? "API connected" : "Connecting…"}
          </span>
          {health && <span className="ml-auto font-mono text-[10px] text-slate-600">v{health.version}</span>}
        </div>
        <p className="mt-2 text-[10px] leading-relaxed text-slate-600">
          Local-first analysis. Source code never leaves this machine except registry metadata queries.
        </p>
      </div>
    </div>
  );
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const { online } = useHealth();
  const title = titles.find(([pattern]) => pattern.test(location.pathname))?.[1] ?? "Dependency Watcher";

  return (
    <div className="min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-border/80 bg-surface/80 backdrop-blur-md lg:block">
        <SidebarContent />
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            aria-label="Close navigation"
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="relative h-full w-72 border-r border-border bg-surface shadow-2xl">
            <button
              aria-label="Close navigation"
              onClick={() => setMobileOpen(false)}
              className="absolute right-3 top-4 z-10 rounded-md p-1.5 text-slate-400 hover:bg-white/5"
            >
              <X className="h-4 w-4" />
            </button>
            <SidebarContent onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      <div className="lg:pl-64">
        <header className="sticky top-0 z-20 border-b border-border/70 bg-background/80 backdrop-blur-xl">
          <div className="flex h-14 items-center gap-3 px-4 sm:px-6 lg:px-8">
            <button
              className="rounded-md p-2 text-slate-400 hover:bg-white/5 hover:text-white lg:hidden"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex min-w-0 items-center gap-2">
              <span className="hidden text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600 sm:inline">
                Workspace /
              </span>
              <span className="truncate text-sm font-medium text-slate-300">{title}</span>
            </div>
            {online === false && (
              <div className="ml-auto flex items-center gap-1.5 rounded-md border border-red-500/25 bg-red-500/10 px-2 py-1 text-[11px] text-red-300">
                <WifiOff className="h-3 w-3" />
                API offline
              </div>
            )}
            <div className="ml-auto hidden items-center gap-2 text-[10px] font-medium uppercase tracking-[0.14em] text-slate-600 sm:flex">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/80" />
              OSV.dev · CycloneDX 1.5
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1500px] px-4 py-6 sm:px-6 sm:py-8 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
