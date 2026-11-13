import { useEffect, useState } from "react";
import { useApiResource } from "@/hooks/useApiResource";
import { api } from "@/lib/api";
import type { Dependency, Health, ScanDetail, ScanSummary, Vulnerability } from "@/types";

const isLiveScan = (data: ScanDetail | null) =>
  data?.status === "pending" || data?.status === "running";

export function useScanDetail(scanId: string | null | undefined) {
  return useApiResource<ScanDetail>(
    () => api.getScan(scanId as string),
    scanId ?? "none",
    { enabled: Boolean(scanId), pollWhile: isLiveScan, pollMs: 2000 },
  );
}

export interface DependencyFilters {
  search: string;
  ecosystem: string;
  severity: string;
  direct: boolean | undefined;
  outdated: boolean | undefined;
  vulnerableOnly: boolean;
}

export function useDependencies(scanId: string | null | undefined, filters: DependencyFilters) {
  const key = JSON.stringify(filters);
  return useApiResource<{ items: Dependency[]; total: number; limit: number; offset: number }>(
    () =>
      api.dependencies(scanId as string, {
        search: filters.search || undefined,
        ecosystem: filters.ecosystem || undefined,
        severity: filters.severity || undefined,
        direct: filters.direct,
        outdated: filters.outdated,
        vulnerable_only: filters.vulnerableOnly || undefined,
        limit: 5000,
      }),
    `${scanId ?? "none"}:${key}`,
    { enabled: Boolean(scanId) },
  );
}

export interface VulnerabilityFilters {
  search: string;
  severity: string;
  ecosystem: string;
}

export function useVulnerabilities(
  scanId: string | null | undefined,
  filters: VulnerabilityFilters,
) {
  const key = JSON.stringify(filters);
  return useApiResource<{ items: Vulnerability[]; total: number; limit: number; offset: number }>(
    () =>
      api.vulnerabilities(scanId as string, {
        search: filters.search || undefined,
        severity: filters.severity || undefined,
        ecosystem: filters.ecosystem || undefined,
        limit: 5000,
      }),
    `${scanId ?? "none"}:${key}`,
    { enabled: Boolean(scanId) },
  );
}

export function useHealth() {
  const [health, setHealth] = useState<Health | null>(null);
  const [online, setOnline] = useState<boolean | null>(null);
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const result = await api.health();
        if (active) {
          setHealth(result);
          setOnline(true);
        }
      } catch {
        if (active) setOnline(false);
      }
    };
    void load();
    const timer = window.setInterval(load, 30_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);
  return { health, online };
}

export function useMeta() {
  return useApiResource(() => api.meta(), "meta");
}

export function useRecentScans(limit = 12) {
  return useApiResource<ScanSummary[]>(
    async () => (await api.listScans({ limit })).items,
    `recent:${limit}`,
  );
}
