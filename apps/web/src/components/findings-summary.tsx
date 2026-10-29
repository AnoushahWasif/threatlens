"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { formatRisk } from "@/components/severity-badge";
import type { Finding } from "@/lib/findings";
import { type PackageRisk, type SeverityCount, summarize } from "@/lib/summary";

const BAR = "var(--color-chart-1)";
const MUTED = "var(--muted-foreground)";
const GRID = "var(--border)";
const ROW_HEIGHT = 34;
const MAX_LABEL = 22;

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
const short = (s: string) => (s.length > MAX_LABEL ? `${s.slice(0, MAX_LABEL - 1)}…` : s);
const packageLabel = (p: PackageRisk) => `${p.name}@${p.version}`;

function Stat({ label, value, note }: { label: string; value: number; note?: string }) {
  return (
    <div className="rounded-lg border p-4">
      <p className="text-muted-foreground text-sm">{label}</p>
      <p className="mt-1 text-3xl font-semibold">{value}</p>
      {note && <p className="text-muted-foreground mt-1 text-xs">{note}</p>}
    </div>
  );
}

function ChartCard({
  title,
  description,
  summary,
  children,
}: {
  title: string;
  description: string;
  summary: string;
  children: React.ReactNode;
}) {
  return (
    <figure className="rounded-lg border p-4">
      <figcaption>
        <p className="font-medium">{title}</p>
        <p className="text-muted-foreground text-sm">{description}</p>
      </figcaption>
      {/* The chart is drawing only; screen readers get the sentence, and the table below. */}
      <div role="img" aria-label={summary} className="mt-3">
        {children}
      </div>
    </figure>
  );
}

const axisProps = {
  tick: { fill: MUTED, fontSize: 12 },
  tickLine: false,
  axisLine: { stroke: GRID },
} as const;

function SeverityChart({ rows }: { rows: SeverityCount[] }) {
  return (
    <ResponsiveContainer width="100%" height={rows.length * ROW_HEIGHT + 30}>
      <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 0 }}>
        <CartesianGrid horizontal={false} stroke={GRID} />
        <XAxis type="number" allowDecimals={false} {...axisProps} />
        <YAxis
          type="category"
          dataKey="severity"
          width={80}
          tickFormatter={capitalize}
          {...axisProps}
        />
        <Tooltip
          cursor={{ fill: "var(--muted)" }}
          formatter={(value, _name, item) => {
            const row = item.payload as SeverityCount;
            return [`${value} (${row.kev} in KEV)`, "Findings"];
          }}
          labelFormatter={(label) => capitalize(String(label))}
        />
        <Bar dataKey="count" fill={BAR} maxBarSize={24} radius={[0, 4, 4, 0]} isAnimationActive={false}>
          <LabelList dataKey="count" position="right" fill="var(--foreground)" fontSize={12} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function PackageChart({ rows }: { rows: PackageRisk[] }) {
  const data = rows.map((p) => ({ ...p, label: packageLabel(p) }));
  return (
    <ResponsiveContainer width="100%" height={rows.length * ROW_HEIGHT + 30}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 0 }}>
        <CartesianGrid horizontal={false} stroke={GRID} />
        <XAxis type="number" domain={[0, 100]} {...axisProps} />
        <YAxis type="category" dataKey="label" width={170} tickFormatter={short} {...axisProps} />
        <Tooltip
          cursor={{ fill: "var(--muted)" }}
          formatter={(value, _name, item) => {
            const row = item.payload as PackageRisk;
            const kev = row.inKev ? ", in KEV" : "";
            return [`${formatRisk(Number(value))} (${plural(row.findings, "finding")}${kev})`, "Highest risk"];
          }}
        />
        <Bar dataKey="maxRisk" fill={BAR} maxBarSize={24} radius={[0, 4, 4, 0]} isAnimationActive={false}>
          <LabelList
            dataKey="maxRisk"
            position="right"
            fill="var(--foreground)"
            fontSize={12}
            formatter={(value) => formatRisk(Number(value))}
          />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function FindingsSummary({ findings }: { findings: Finding[] }) {
  const s = summarize(findings);
  if (s.total === 0) return null;

  const worst = s.bySeverity.filter((r) => r.count > 0);
  const severitySentence = worst.map((r) => `${r.count} ${r.severity}`).join(", ");
  const top = s.topPackages[0];

  return (
    <section aria-label="Summary" className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Findings" value={s.total} />
        <Stat label="In CISA KEV" value={s.kev} note="Known to be exploited" />
        <Stat label="Not scored" value={s.unscored} note="No EPSS or KEV data" />
        <Stat label="Packages affected" value={s.packages} />
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard
          title="Findings by severity"
          description="Count per severity level"
          summary={`Findings by severity: ${severitySentence}.`}
        >
          <SeverityChart rows={s.bySeverity} />
        </ChartCard>

        <ChartCard
          title="Riskiest packages"
          description="Highest risk score per package (0–100)"
          summary={
            top
              ? `Riskiest package: ${packageLabel(top)} at ${formatRisk(top.maxRisk)}.`
              : "No package has a risk score yet."
          }
        >
          {s.topPackages.length > 0 ? (
            <PackageChart rows={s.topPackages} />
          ) : (
            <p className="text-muted-foreground py-6 text-center text-sm">
              No risk scores yet: EPSS and KEV data were unavailable for every finding.
            </p>
          )}
          {s.unscoredPackages > 0 && (
            <p className="text-muted-foreground mt-2 text-xs">
              {plural(s.unscoredPackages, "package")} not shown: none of their findings could be
              scored, which isn&apos;t the same as low risk.
            </p>
          )}
        </ChartCard>
      </div>

      <details className="text-sm">
        <summary className="text-muted-foreground cursor-pointer">Show chart data as a table</summary>
        <div className="mt-3 grid gap-6 lg:grid-cols-2">
          <table className="w-full text-left">
            <caption className="text-muted-foreground mb-1 text-left">Findings by severity</caption>
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col" className="text-right">Findings</th>
                <th scope="col" className="text-right">In KEV</th>
              </tr>
            </thead>
            <tbody>
              {s.bySeverity.map((r) => (
                <tr key={r.severity}>
                  <td>{capitalize(r.severity)}</td>
                  <td className="text-right tabular-nums">{r.count}</td>
                  <td className="text-right tabular-nums">{r.kev}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <table className="w-full text-left">
            <caption className="text-muted-foreground mb-1 text-left">Riskiest packages</caption>
            <thead>
              <tr>
                <th scope="col">Package</th>
                <th scope="col" className="text-right">Highest risk</th>
                <th scope="col" className="text-right">Findings</th>
              </tr>
            </thead>
            <tbody>
              {s.topPackages.map((p) => (
                <tr key={p.key}>
                  <td className="break-all">{packageLabel(p)}</td>
                  <td className="text-right tabular-nums">{formatRisk(p.maxRisk)}</td>
                  <td className="text-right tabular-nums">{p.findings}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
