import type {
  CompareResult,
  CreateScanInput,
  Dependency,
  Health,
  Meta,
  Paged,
  Remediation,
  ScanDetail,
  ScanSummary,
  Settings,
  SettingsUpdate,
  Vulnerability,
} from "@/types";

const API_BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? "/api";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
        ...init?.headers,
      },
    });
  } catch {
    throw new ApiError(
      "Cannot reach the Dependency Watcher API. Is the backend running on port 8000?",
      0,
    );
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = (await response.json()) as { detail?: string | Array<{ msg?: string }> };
      if (typeof payload.detail === "string") message = payload.detail;
      else if (Array.isArray(payload.detail)) {
        message = payload.detail.map((item) => item.msg ?? "Invalid value").join(", ");
      }
    } catch {
      // Keep the status fallback when the body is not JSON.
    }
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const suffix = search.toString();
  return suffix ? `?${suffix}` : "";
}

export const api = {
  health: () => request<Health>("/health"),
  meta: () => request<Meta>("/meta"),
  settings: () => request<Settings>("/settings"),
  updateSettings: (payload: SettingsUpdate) =>
    request<Settings>("/settings", { method: "PUT", body: JSON.stringify(payload) }),
  clearCache: () => request<{ status: string }>("/settings/cache", { method: "DELETE" }),

  listScans: (params: { status?: string; limit?: number; offset?: number } = {}) =>
    request<Paged<ScanSummary>>(`/scans${query(params)}`),
  getScan: (id: string) => request<ScanDetail>(`/scans/${id}`),
  createScan: (payload: CreateScanInput) =>
    request<ScanDetail>("/scans", { method: "POST", body: JSON.stringify(payload) }),
  uploadScan: (file: File, projectName?: string) => {
    const form = new FormData();
    form.append("file", file);
    if (projectName?.trim()) form.append("project_name", projectName.trim());
    return request<ScanDetail>("/scans/upload", { method: "POST", body: form });
  },
  deleteScan: (id: string) => request<void>(`/scans/${id}`, { method: "DELETE" }),

  dependencies: (
    scanId: string,
    params: {
      search?: string;
      ecosystem?: string;
      severity?: string;
      inspection_status?: string;
      direct?: boolean;
      outdated?: boolean;
      vulnerable_only?: boolean;
      limit?: number;
      offset?: number;
    } = {},
  ) => request<Paged<Dependency>>(`/scans/${scanId}/dependencies${query(params)}`),
  dependency: (scanId: string, dependencyId: number) =>
    request<Dependency>(`/scans/${scanId}/dependencies/${dependencyId}`),
  vulnerabilities: (
    scanId: string,
    params: {
      search?: string;
      severity?: string;
      ecosystem?: string;
      include_details?: boolean;
      limit?: number;
      offset?: number;
    } = {},
  ) => request<Paged<Vulnerability>>(`/scans/${scanId}/vulnerabilities${query(params)}`),
  vulnerability: (id: number) => request<Vulnerability>(`/vulnerabilities/${id}`),
  remediation: (scanId: string) => request<Remediation>(`/scans/${scanId}/remediation`),
  compare: (a: string, b: string) => request<CompareResult>(`/compare${query({ scan_a: a, scan_b: b })}`),
};

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

export function reportUrl(scanId: string, format: "json" | "html" | "csv" | "pdf"): string {
  return apiUrl(`/scans/${scanId}/reports/${format}`);
}

export function sbomUrl(scanId: string, format: "json" | "xml"): string {
  return apiUrl(`/scans/${scanId}/sbom?format=${format}`);
}

export function triggerDownload(url: string, filename?: string): void {
  const anchor = document.createElement("a");
  anchor.href = url;
  if (filename) anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}
