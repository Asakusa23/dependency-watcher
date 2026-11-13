import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Eraser,
  Github,
  Globe2,
  KeyRound,
  LoaderCircle,
  Save,
  Settings2,
  ShieldCheck,
  Timer,
} from "lucide-react";
import { useApiResource } from "@/hooks/useApiResource";
import { api } from "@/lib/api";
import type { Meta, Settings } from "@/types";
import { PageHeader, ErrorState, Skeleton } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface FormState {
  allow_local_paths: boolean;
  enable_osv: boolean;
  enable_registry: boolean;
  enable_nvd: boolean;
  enable_github: boolean;
  http_timeout_seconds: number;
  cache_ttl_seconds: number;
}

const defaults: FormState = {
  allow_local_paths: true,
  enable_osv: true,
  enable_registry: true,
  enable_nvd: false,
  enable_github: true,
  http_timeout_seconds: 20,
  cache_ttl_seconds: 21600,
};

export function SettingsPage() {
  const settings = useApiResource<Settings>(() => api.settings(), "settings");
  const meta = useApiResource<Meta>(() => api.meta(), "meta");
  const [form, setForm] = useState<FormState>(defaults);
  const [nvdKey, setNvdKey] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [clearNvd, setClearNvd] = useState(false);
  const [clearGithub, setClearGithub] = useState(false);
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  useEffect(() => {
    if (settings.data) {
      setForm({
        allow_local_paths: settings.data.allow_local_paths,
        enable_osv: settings.data.enable_osv,
        enable_registry: settings.data.enable_registry,
        enable_nvd: settings.data.enable_nvd,
        enable_github: settings.data.enable_github,
        http_timeout_seconds: settings.data.http_timeout_seconds,
        cache_ttl_seconds: settings.data.cache_ttl_seconds,
      });
    }
  }, [settings.data]);

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setMessage(null);
    try {
      await api.updateSettings({
        ...form,
        ...(nvdKey.trim() ? { nvd_api_key: nvdKey.trim() } : {}),
        ...(githubToken.trim() ? { github_token: githubToken.trim() } : {}),
        clear_nvd_api_key: clearNvd,
        clear_github_token: clearGithub,
      });
      setNvdKey("");
      setGithubToken("");
      setClearNvd(false);
      setClearGithub(false);
      settings.reload();
      setMessage({ kind: "ok", text: "Settings saved. New scans will use this configuration." });
    } catch (error) {
      setMessage({ kind: "error", text: error instanceof Error ? error.message : "Failed to save settings" });
    } finally {
      setSaving(false);
    }
  };

  const clearCache = async () => {
    if (!window.confirm("Clear cached OSV and registry responses? The next scan will make fresh network requests.")) return;
    setClearing(true);
    setMessage(null);
    try {
      await api.clearCache();
      setMessage({ kind: "ok", text: "Vulnerability and registry cache cleared." });
    } catch (error) {
      setMessage({ kind: "error", text: error instanceof Error ? error.message : "Failed to clear cache" });
    } finally {
      setClearing(false);
    }
  };

  if (settings.loading && !settings.data) {
    return (
      <div className="space-y-6">
        <PageHeader eyebrow="Configuration" title="Settings" />
        <Skeleton className="h-[300px] w-full" />
        <Skeleton className="h-[240px] w-full" />
      </div>
    );
  }
  if (settings.error && !settings.data) {
    return <ErrorState message={settings.error} onRetry={settings.reload} />;
  }

  const servers = [
    {
      key: "enable_osv" as const,
      title: "OSV.dev advisories",
      description: "Primary vulnerability source. Disabling this makes it impossible to report advisories.",
      icon: ShieldCheck,
      critical: true,
    },
    {
      key: "enable_registry" as const,
      title: "Package registries",
      description: "Latest versions, licenses, release dates and explicit deprecation metadata.",
      icon: Globe2,
    },
    {
      key: "enable_nvd" as const,
      title: "NVD CVSS enrichment",
      description: "Optional secondary source. Uses an API key when configured; slower without one.",
      icon: Database,
    },
    {
      key: "enable_github" as const,
      title: "GitHub repository scans",
      description: "Allow fetching public GitHub repositories with SSRF and archive protections.",
      icon: Github,
    },
    {
      key: "allow_local_paths" as const,
      title: "Local path scans",
      description: "Allow the API to read local directories. Keep enabled for desktop use; disable for shared deployments.",
      icon: Settings2,
    },
  ];

  return (
    <form onSubmit={save} className="space-y-6">
      <PageHeader
        eyebrow="Configuration"
        title="Settings"
        description="Control evidence sources, network behavior and cache retention. Changes apply to new scans."
        actions={
          <Button type="submit" size="sm" disabled={saving}>
            {saving ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            {saving ? "Saving…" : "Save settings"}
          </Button>
        }
      />

      {message && (
        <div
          className={cn(
            "flex items-start gap-2 rounded-lg border px-4 py-3 text-xs",
            message.kind === "ok"
              ? "border-emerald-500/25 bg-emerald-500/[0.05] text-emerald-200/85"
              : "border-red-500/25 bg-red-500/[0.05] text-red-200/85",
          )}
        >
          {message.kind === "ok" ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5" /> : <AlertTriangle className="mt-0.5 h-3.5 w-3.5" />}
          {message.text}
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-12">
        <div className="space-y-4 xl:col-span-7">
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Evidence sources</CardTitle>
                <CardDescription>External services queried during a scan.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-1">
              {servers.map((server) => (
                <div key={server.key} className="flex items-start gap-3 border-b border-border/60 py-3.5 last:border-0">
                  <div className={cn("mt-0.5 rounded-md border border-border bg-surface p-1.5", server.critical ? "text-blue-300" : "text-slate-500")}>
                    <server.icon className="h-3.5 w-3.5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-slate-200">{server.title}</span>
                      {server.critical && <Badge className="border-blue-500/20 text-[9px] text-blue-300">primary</Badge>}
                    </div>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">{server.description}</p>
                  </div>
                  <Switch
                    checked={form[server.key]}
                    onCheckedChange={(checked) => setForm((current) => ({ ...current, [server.key]: checked }))}
                    aria-label={`Toggle ${server.title}`}
                  />
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div>
                <CardTitle>API credentials</CardTitle>
                <CardDescription>Optional. Secrets are stored locally and never returned by the API.</CardDescription>
              </div>
              <KeyRound className="h-4 w-4 text-slate-600" />
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="nvd-key">NVD API key</Label>
                  {settings.data?.nvd_api_key_configured && (
                    <Badge className="border-emerald-500/20 bg-emerald-500/[0.06] text-[9px] text-emerald-300">configured</Badge>
                  )}
                </div>
                <Input
                  id="nvd-key"
                  type="password"
                  value={nvdKey}
                  onChange={(event) => setNvdKey(event.target.value)}
                  placeholder={settings.data?.nvd_api_key_configured ? "Enter a replacement key…" : "Optional NVD API key"}
                  autoComplete="off"
                  disabled={clearNvd}
                />
                {settings.data?.nvd_api_key_configured && (
                  <label className="mt-1.5 flex items-center gap-1.5 text-[10px] text-slate-500">
                    <input type="checkbox" checked={clearNvd} onChange={(event) => setClearNvd(event.target.checked)} className="accent-red-500" />
                    Remove stored NVD key on save
                  </label>
                )}
              </div>
              <div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="github-token">GitHub token</Label>
                  {settings.data?.github_token_configured && (
                    <Badge className="border-emerald-500/20 bg-emerald-500/[0.06] text-[9px] text-emerald-300">configured</Badge>
                  )}
                </div>
                <Input
                  id="github-token"
                  type="password"
                  value={githubToken}
                  onChange={(event) => setGithubToken(event.target.value)}
                  placeholder={settings.data?.github_token_configured ? "Enter a replacement token…" : "Optional token for higher GitHub limits"}
                  autoComplete="off"
                  disabled={clearGithub}
                />
                {settings.data?.github_token_configured && (
                  <label className="mt-1.5 flex items-center gap-1.5 text-[10px] text-slate-500">
                    <input type="checkbox" checked={clearGithub} onChange={(event) => setClearGithub(event.target.checked)} className="accent-red-500" />
                    Remove stored GitHub token on save
                  </label>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4 xl:col-span-5">
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Network behavior</CardTitle>
                <CardDescription>Timeouts and response caching.</CardDescription>
              </div>
              <Timer className="h-4 w-4 text-slate-600" />
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="timeout">HTTP timeout (seconds)</Label>
                <Input
                  id="timeout"
                  type="number"
                  min={3}
                  max={120}
                  value={form.http_timeout_seconds}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, http_timeout_seconds: Number(event.target.value) }))
                  }
                />
                <p className="mt-1 text-[10px] text-slate-600">Applies to OSV, NVD, registry and GitHub requests.</p>
              </div>
              <div>
                <Label htmlFor="ttl">Cache TTL (seconds)</Label>
                <Input
                  id="ttl"
                  type="number"
                  min={60}
                  max={604800}
                  value={form.cache_ttl_seconds}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, cache_ttl_seconds: Number(event.target.value) }))
                  }
                />
                <p className="mt-1 text-[10px] text-slate-600">
                  Default 21600 seconds (6 hours). Cached responses reduce registry and OSV load.
                </p>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border bg-surface p-3">
                <div>
                  <div className="text-xs font-medium text-slate-300">Response cache</div>
                  <div className="mt-0.5 text-[10px] text-slate-600">SQLite-backed with TTL</div>
                </div>
                <Button type="button" variant="danger" size="sm" onClick={() => void clearCache()} disabled={clearing}>
                  {clearing ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Eraser className="h-3.5 w-3.5" />}
                  Clear
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div>
                <CardTitle>Runtime limits</CardTitle>
                <CardDescription>Enforced by the scan engine.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {meta.data ? (
                <>
                  <Limit label="Max upload" value={formatBytes(meta.data.limits.max_upload_bytes)} />
                  <Limit label="Max extracted" value={formatBytes(meta.data.limits.max_extracted_bytes)} />
                  <Limit label="Max archive files" value={meta.data.limits.max_archive_files.toLocaleString()} />
                  <Limit label="Max project files" value={meta.data.limits.max_project_files.toLocaleString()} />
                  <Limit label="Max dependencies" value={meta.data.limits.max_dependencies.toLocaleString()} />
                  <div className="mt-3 border-t border-border/60 pt-3">
                    <p className="eyebrow mb-2">Supported manifests</p>
                    <div className="flex max-h-40 flex-wrap gap-1 overflow-y-auto">
                      {meta.data.dependency_files.map((file) => (
                        <span key={file} className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-[9px] text-slate-500">{file}</span>
                      ))}
                    </div>
                  </div>
                </>
              ) : (
                <Skeleton className="h-32 w-full" />
              )}
            </CardContent>
          </Card>

          <div className="rounded-xl border border-blue-500/15 bg-blue-500/[0.04] p-4">
            <p className="flex items-center gap-1.5 text-xs font-medium text-blue-200">
              <ShieldCheck className="h-3.5 w-3.5" />
              Local security model
            </p>
            <ul className="mt-2 space-y-1.5 text-[10px] leading-relaxed text-slate-500">
              <li>• The API binds to localhost by default; do not expose it without authentication.</li>
              <li>• Local path scans are disabled only in the UI here — configure env allowlists for shared hosts.</li>
              <li>• GitHub fetches require HTTPS, host allowlisting, public DNS resolution and archive limits.</li>
              <li>• Scanned project code is parsed as data and never executed or installed.</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between rounded-xl border border-border bg-surface/60 px-4 py-3">
        <p className="text-[10px] text-slate-600">
          API version {meta.data?.version ?? "—"} · settings file permissions restricted to the local user
        </p>
        <Button type="submit" size="sm" disabled={saving}>
          {saving ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
          Save settings
        </Button>
      </div>
    </form>
  );
}

function Limit({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-[11px]">
      <span className="text-slate-500">{label}</span>
      <span className="font-mono text-slate-300">{value}</span>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (!bytes) return "—";
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
  return `${Math.round(bytes / 1024 / 1024)} MB`;
}
