import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Line,
  Pie,
  PieChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ScanSummary, Severity } from "@/types";
import { formatShortDate, scoreColor, scoreLabel } from "@/lib/format";
import { severityHex } from "@/components/ui/badges";

const darkTooltip = {
  contentStyle: {
    background: "#0f1724",
    border: "1px solid #243247",
    borderRadius: 10,
    fontSize: 12,
    color: "#dbe4f0",
  },
  labelStyle: { color: "#94a3b8", marginBottom: 4 },
  itemStyle: { color: "#dbe4f0" },
};

export function ScoreGauge({
  score,
  grade,
  height = 190,
}: {
  score?: number | null;
  grade?: string | null;
  height?: number;
}) {
  const value = score ?? 0;
  const color = scoreColor(score);
  return (
    <div className="relative" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart
          cx="50%"
          cy="58%"
          innerRadius="72%"
          outerRadius="100%"
          barSize={12}
          startAngle={210}
          endAngle={-30}
          data={[{ value, fill: color }]}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar background={{ fill: "#162235" }} dataKey="value" cornerRadius={8} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pt-5">
        <div className="flex items-baseline gap-1">
          <span className="font-mono text-4xl font-semibold tracking-tight" style={{ color }}>
            {score == null ? "—" : Math.round(score)}
          </span>
          <span className="text-xs text-slate-600">/100</span>
        </div>
        <span className="mt-1 text-[11px] font-medium text-slate-400">{scoreLabel(score)}</span>
        <span className="mt-0.5 font-mono text-[10px] text-slate-600">GRADE {grade ?? "—"}</span>
      </div>
    </div>
  );
}

const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function SeverityDonut({ scan }: { scan: ScanSummary }) {
  const data = [
    { name: "Critical", value: scan.critical_count, severity: "CRITICAL" as Severity },
    { name: "High", value: scan.high_count, severity: "HIGH" as Severity },
    { name: "Medium", value: scan.medium_count, severity: "MEDIUM" as Severity },
    { name: "Low", value: scan.low_count, severity: "LOW" as Severity },
    { name: "Info", value: scan.info_count, severity: "INFO" as Severity },
  ].filter((item) => item.value > 0);
  const total = data.reduce((sum, item) => sum + item.value, 0);

  if (!total) {
    return (
      <div className="flex h-[220px] flex-col items-center justify-center text-center">
        <div className="flex h-28 w-28 items-center justify-center rounded-full border-[10px] border-emerald-500/20 font-mono text-2xl text-emerald-400">
          0
        </div>
        <p className="mt-3 text-xs text-muted">No advisories matched checked components.</p>
      </div>
    );
  }

  return (
    <div className="grid items-center gap-3 sm:grid-cols-[1.1fr_.9fr]">
      <div className="relative h-[210px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="64%"
              outerRadius="94%"
              paddingAngle={3}
              stroke="none"
            >
              {data.map((entry) => (
                <Cell key={entry.severity} fill={severityHex[entry.severity]} />
              ))}
            </Pie>
            <Tooltip {...darkTooltip} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-3xl font-semibold text-slate-100">{total}</span>
          <span className="text-[10px] uppercase tracking-wider text-slate-500">findings</span>
        </div>
      </div>
      <div className="space-y-2">
        {severityOrder.map((severity) => {
          const item = data.find((entry) => entry.severity === severity);
          if (!item) return null;
          return (
            <div key={severity} className="flex items-center gap-2 text-xs">
              <span className="h-2 w-2 rounded-sm" style={{ background: severityHex[severity] }} />
              <span className="w-14 text-slate-400">{item.name}</span>
              <span className="ml-auto font-mono text-slate-200">{item.value}</span>
              <span className="w-10 text-right font-mono text-[10px] text-slate-600">
                {total ? Math.round((item.value / total) * 100) : 0}%
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function EcosystemBars({ data }: { data: Array<{ name: string; value: number }> }) {
  const filtered = data.filter((entry) => entry.value > 0);
  if (!filtered.length) {
    return <div className="flex h-[200px] items-center justify-center text-xs text-muted">No findings by ecosystem.</div>;
  }
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={filtered} layout="vertical" margin={{ top: 4, right: 12, bottom: 4, left: 0 }}>
        <CartesianGrid stroke="#1d293b" strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" allowDecimals={false} tick={{ fill: "#66758b", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis
          type="category"
          dataKey="name"
          width={78}
          tick={{ fill: "#94a3b8", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip {...darkTooltip} cursor={{ fill: "rgba(148,163,184,.05)" }} />
        <Bar dataKey="value" name="Findings" radius={[0, 5, 5, 0]} barSize={14}>
          {filtered.map((entry, index) => (
            <Cell key={entry.name} fill={["#3b82f6", "#0ea5e9", "#8b5cf6", "#06b6d4"][index % 4]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function HistoryChart({ scans }: { scans: ScanSummary[] }) {
  const completed = scans
    .filter((scan) => scan.status === "completed" && scan.completed_at)
    .slice(0, 12)
    .reverse();
  const data = completed.map((scan) => ({
    name: formatShortDate(scan.completed_at),
    score: scan.security_score ?? 0,
    vulnerabilities: scan.vulnerability_count,
    project: scan.project_name,
  }));
  if (data.length === 0) {
    return <div className="flex h-[220px] items-center justify-center text-xs text-muted">Complete a scan to build history.</div>;
  }
  return (
    <ResponsiveContainer width="100%" height={230}>
      <ComposedChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: -18 }}>
        <CartesianGrid stroke="#1d293b" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: "#66758b", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis yAxisId="left" domain={[0, 100]} tick={{ fill: "#66758b", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis
          yAxisId="right"
          orientation="right"
          tick={{ fill: "#66758b", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          {...darkTooltip}
          formatter={(value, name) => [
            name === "score" ? `${value}/100` : String(value),
            name === "score" ? "Security score" : "Vulnerabilities",
          ]}
        />
        <Bar yAxisId="right" dataKey="vulnerabilities" fill="#ef4444" opacity={0.25} radius={[4, 4, 0, 0]} barSize={18} />
        <Line
          yAxisId="left"
          type="monotone"
          dataKey="score"
          stroke="#60a5fa"
          strokeWidth={2}
          dot={{ fill: "#0b111b", stroke: "#60a5fa", strokeWidth: 2, r: 3 }}
          activeDot={{ r: 4 }}
        />
      </ComposedChart>
    </ResponsiveContainer>
  );
}
