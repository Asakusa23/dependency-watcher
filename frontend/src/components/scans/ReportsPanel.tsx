import { FileCode2, FileJson, FileSpreadsheet, FileText, PackageCheck, Braces, Download, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { reportUrl, sbomUrl } from "@/lib/api";
import type { ScanDetail } from "@/types";
import { cn } from "@/lib/utils";

const reports = [
  {
    format: "pdf" as const,
    title: "Executive PDF",
    description: "Shareable security report with findings and remediation guidance.",
    icon: FileText,
    accent: "text-red-300 border-red-500/20 bg-red-500/[0.06]",
  },
  {
    format: "html" as const,
    title: "Interactive HTML",
    description: "Self-contained overview that opens directly in a browser.",
    icon: FileCode2,
    accent: "text-orange-300 border-orange-500/20 bg-orange-500/[0.06]",
  },
  {
    format: "json" as const,
    title: "Structured JSON",
    description: "Complete machine-readable scan result and score breakdown.",
    icon: FileJson,
    accent: "text-blue-300 border-blue-500/20 bg-blue-500/[0.06]",
  },
  {
    format: "csv" as const,
    title: "Component CSV",
    description: "Dependency inventory with severity and freshness columns.",
    icon: FileSpreadsheet,
    accent: "text-emerald-300 border-emerald-500/20 bg-emerald-500/[0.06]",
  },
];

export function ReportsPanel({ scan }: { scan: ScanDetail }) {
  const disabled = scan.status !== "completed";
  return (
    <div className="space-y-4">
      {disabled && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.05] px-4 py-3 text-xs text-amber-200/80">
          Reports become available after the scan completes.
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        {reports.map((report) => (
          <a
            key={report.format}
            href={disabled ? undefined : reportUrl(scan.id, report.format)}
            target={report.format === "html" ? "_blank" : undefined}
            rel="noopener noreferrer"
            download={report.format !== "html" ? true : undefined}
            aria-disabled={disabled}
            className={cn(
              "panel panel-hover group flex items-start gap-3 p-4",
              disabled && "pointer-events-none opacity-40",
            )}
          >
            <div className={cn("rounded-lg border p-2", report.accent)}>
              <report.icon className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-sm font-medium text-slate-200">{report.title}</h3>
                <Download className="h-3.5 w-3.5 text-slate-600 transition-colors group-hover:text-slate-300" />
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-muted">{report.description}</p>
            </div>
          </a>
        ))}
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle className="flex items-center gap-2">
              <PackageCheck className="h-4 w-4 text-blue-400" />
              CycloneDX 1.5 SBOM
            </CardTitle>
            <CardDescription>
              Portable software bill of materials for supply-chain exchange and downstream tooling.
            </CardDescription>
          </div>
          {scan.sbom_serial && <Badge className="font-mono text-[9px]">{scan.sbom_serial.slice(0, 13)}…</Badge>}
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row">
          <a
            href={disabled ? undefined : sbomUrl(scan.id, "json")}
            download
            aria-disabled={disabled}
            className={cn(
              "flex flex-1 items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs text-slate-300 transition-colors hover:border-slate-500 hover:text-white",
              disabled && "pointer-events-none opacity-40",
            )}
          >
            <Braces className="h-4 w-4 text-blue-400" />
            CycloneDX JSON
            <Download className="ml-auto h-3.5 w-3.5 text-slate-600" />
          </a>
          <a
            href={disabled ? undefined : sbomUrl(scan.id, "xml")}
            download
            aria-disabled={disabled}
            className={cn(
              "flex flex-1 items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-xs text-slate-300 transition-colors hover:border-slate-500 hover:text-white",
              disabled && "pointer-events-none opacity-40",
            )}
          >
            <FileCode2 className="h-4 w-4 text-violet-400" />
            CycloneDX XML
            <Download className="ml-auto h-3.5 w-3.5 text-slate-600" />
          </a>
        </CardContent>
      </Card>

      <div className="grid gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Manifest files</CardTitle>
              <CardDescription>Files that contributed components to this scan.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {scan.dependency_files.length ? (
              <div className="flex flex-wrap gap-1.5">
                {scan.dependency_files.map((file) => (
                  <span key={file} className="rounded-md border border-border bg-surface px-2 py-1 font-mono text-[10px] text-slate-400">
                    {file}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-600">No manifest files recorded.</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <div>
              <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                Evidence sources
              </CardTitle>
              <CardDescription>Every source used to produce this result.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5">
              {scan.sources_used.map((source) => (
                <li key={source} className="flex items-center gap-2 text-xs text-slate-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/60" />
                  {source}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
