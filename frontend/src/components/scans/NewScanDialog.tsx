import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  Archive,
  ArrowRight,
  Cloud,
  FolderSearch,
  LoaderCircle,
  UploadCloud,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/form";
import { api } from "@/lib/api";
import { useScans } from "@/context/ScanContext";
import { useMeta } from "@/hooks/useApiData";
import { cn } from "@/lib/utils";
import type { ScanDetail } from "@/types";

type Mode = "local" | "upload" | "github";

const modes: Array<{ id: Mode; label: string; icon: typeof FolderSearch; hint: string }> = [
  { id: "local", label: "Local path", icon: FolderSearch, hint: "Scan a directory on this machine" },
  { id: "upload", label: "Upload ZIP", icon: UploadCloud, hint: "Analyze an archive safely" },
  { id: "github", label: "GitHub", icon: Cloud, hint: "Fetch a public repository" },
];

export function NewScanDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (scan: ScanDetail) => void;
}) {
  const [mode, setMode] = useState<Mode>("local");
  const [path, setPath] = useState("");
  const [repository, setRepository] = useState("");
  const [projectName, setProjectName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const { refresh } = useScans();
  const meta = useMeta();

  useEffect(() => {
    if (!open) {
      setError(null);
      setBusy(false);
    }
  }, [open]);

  const reset = () => {
    setPath("");
    setRepository("");
    setProjectName("");
    setFile(null);
    setError(null);
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setError(null);
    if (mode === "local" && !path.trim()) {
      setError("Enter an absolute path to a project directory.");
      return;
    }
    if (mode === "github" && !repository.trim()) {
      setError("Enter a GitHub repository URL.");
      return;
    }
    if (mode === "upload" && !file) {
      setError("Choose a ZIP archive to scan.");
      return;
    }
    setBusy(true);
    try {
      let scan: ScanDetail;
      if (mode === "upload" && file) {
        scan = await api.uploadScan(file, projectName);
      } else {
        scan = await api.createScan({
          source_type: mode === "github" ? "github" : "local",
          path: mode === "local" ? path.trim() : undefined,
          repository_url: mode === "github" ? repository.trim() : undefined,
          project_name: projectName.trim() || undefined,
        });
      }
      reset();
      onOpenChange(false);
      void refresh();
      onCreated?.(scan);
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to start scan");
    } finally {
      setBusy(false);
    }
  };

  const chooseFile = (selected: File | null) => {
    setError(null);
    if (selected && !selected.name.toLowerCase().endsWith(".zip")) {
      setError("Only .zip archives are supported.");
      return;
    }
    setFile(selected);
  };

  const activeMode = modes.find((item) => item.id === mode)!;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogTitle>Run a new scan</DialogTitle>
        <DialogDescription>
          Dependency Watcher parses manifests, queries OSV.dev and package registries, and stores the
          result locally. Scanned code is never executed.
        </DialogDescription>

        <div className="mt-5 grid gap-2 sm:grid-cols-3">
          {modes.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setMode(item.id);
                setError(null);
              }}
              className={cn(
                "rounded-lg border p-3 text-left transition-colors",
                mode === item.id
                  ? "border-blue-500/40 bg-blue-500/10"
                  : "border-border bg-surface hover:border-slate-600",
              )}
            >
              <item.icon className={cn("h-4 w-4", mode === item.id ? "text-blue-400" : "text-slate-500")} />
              <div className="mt-2 text-xs font-semibold text-slate-200">{item.label}</div>
              <div className="mt-1 text-[10px] leading-relaxed text-slate-500">{item.hint}</div>
            </button>
          ))}
        </div>

        <form onSubmit={submit} className="mt-5 space-y-4">
          {mode === "local" && (
            <div>
              <Label htmlFor="scan-path">Project directory</Label>
              <Input
                id="scan-path"
                value={path}
                onChange={(event) => setPath(event.target.value)}
                placeholder="E:\projects\my-application"
                autoComplete="off"
                spellCheck={false}
                autoFocus
              />
              <p className="mt-1.5 text-[11px] text-slate-500">
                The backend must be able to read this path. Manifest discovery is recursive and
                bounded by configured limits.
              </p>
            </div>
          )}

          {mode === "github" && (
            <div>
              <Label htmlFor="scan-repo">Repository URL</Label>
              <Input
                id="scan-repo"
                value={repository}
                onChange={(event) => setRepository(event.target.value)}
                placeholder="https://github.com/owner/repository"
                autoComplete="off"
                spellCheck={false}
                autoFocus
              />
              <p className="mt-1.5 text-[11px] text-slate-500">
                Only allowlisted GitHub hosts and HTTPS URLs are accepted. Archives are size-limited
                and symlinks are rejected.
              </p>
            </div>
          )}

          {mode === "upload" && (
            <div>
              <Label>ZIP archive</Label>
              <input
                ref={fileInput}
                type="file"
                accept=".zip,application/zip"
                className="sr-only"
                onChange={(event) => chooseFile(event.target.files?.[0] ?? null)}
              />
              <button
                type="button"
                onClick={() => fileInput.current?.click()}
                onDragOver={(event) => {
                  event.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => {
                  event.preventDefault();
                  setDragging(false);
                  chooseFile(event.dataTransfer.files?.[0] ?? null);
                }}
                className={cn(
                  "flex w-full flex-col items-center justify-center rounded-xl border border-dashed px-4 py-8 text-center transition-colors",
                  dragging
                    ? "border-blue-400/60 bg-blue-500/10"
                    : "border-border bg-surface hover:border-slate-500",
                )}
              >
                <Archive className="mb-2 h-6 w-6 text-slate-500" />
                {file ? (
                  <>
                    <span className="text-sm font-medium text-slate-200">{file.name}</span>
                    <span className="mt-1 text-[11px] text-muted">
                      {(file.size / 1024 / 1024).toFixed(2)} MB · click to replace
                    </span>
                  </>
                ) : (
                  <>
                    <span className="text-sm font-medium text-slate-300">Drop a ZIP here or browse</span>
                    <span className="mt-1 text-[11px] text-muted">
                      Maximum {Math.round((meta.data?.limits.max_upload_bytes ?? 0) / 1024 / 1024)} MB
                    </span>
                  </>
                )}
              </button>
            </div>
          )}

          <div>
            <Label htmlFor="scan-name">Project name <span className="text-slate-600">(optional)</span></Label>
            <Input
              id="scan-name"
              value={projectName}
              onChange={(event) => setProjectName(event.target.value)}
              placeholder="Defaults to the directory, archive, or repository name"
              maxLength={255}
            />
          </div>

          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-red-500/25 bg-red-500/[0.07] p-3 text-xs text-red-300">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {error}
            </div>
          )}

          <div className="flex items-center justify-between gap-3 border-t border-border pt-4">
            <p className="hidden text-[10px] leading-relaxed text-slate-600 sm:block">
              {activeMode.hint}. No package installation.
            </p>
            <div className="ml-auto flex gap-2">
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
                Cancel
              </Button>
              <Button type="submit" disabled={busy}>
                {busy ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ArrowRight className="h-4 w-4" />}
                {busy ? "Starting…" : "Start scan"}
              </Button>
            </div>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
