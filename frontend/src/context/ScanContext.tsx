import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { ScanSummary } from "@/types";

const STORAGE_KEY = "dw.activeScanId";

interface ScanContextValue {
  scans: ScanSummary[];
  activeScan: ScanSummary | null;
  activeScanId: string | null;
  setActiveScanId: (id: string) => void;
  refresh: () => Promise<void>;
  loading: boolean;
  refreshing: boolean;
  error: string | null;
}

const ScanContext = createContext<ScanContextValue | null>(null);

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [activeScanId, setActiveId] = useState<string | null>(() => {
    try {
      return window.localStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setRefreshing(true);
    try {
      const page = await api.listScans({ limit: 100 });
      setScans(page.items);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scans");
    } finally {
      inFlight.current = false;
      setRefreshing(false);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const hasLiveScan = scans.some((scan) => scan.status === "pending" || scan.status === "running");
    if (!hasLiveScan) return;
    const timer = window.setInterval(() => void refresh(), 2500);
    return () => window.clearInterval(timer);
  }, [scans, refresh]);

  const completed = useMemo(() => scans.filter((scan) => scan.status === "completed"), [scans]);

  useEffect(() => {
    if (!scans.length) return;
    const current = activeScanId ? scans.find((scan) => scan.id === activeScanId) : undefined;
    if (current) return;
    const fallback = completed[0] ?? scans[0];
    if (fallback) setActiveId(fallback.id);
  }, [activeScanId, completed, scans]);

  useEffect(() => {
    if (!activeScanId) return;
    try {
      window.localStorage.setItem(STORAGE_KEY, activeScanId);
    } catch {
      // Storage can be unavailable in private browsing; selection still works in memory.
    }
  }, [activeScanId]);

  const setActiveScanId = useCallback((id: string) => setActiveId(id), []);
  const activeScan = scans.find((scan) => scan.id === activeScanId) ?? null;

  const value = useMemo(
    () => ({ scans, activeScan, activeScanId, setActiveScanId, refresh, loading, refreshing, error }),
    [scans, activeScan, activeScanId, setActiveScanId, refresh, loading, refreshing, error],
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScans(): ScanContextValue {
  const context = useContext(ScanContext);
  if (!context) throw new Error("useScans must be used within ScanProvider");
  return context;
}
