import type { Severity } from "@/lib/findings";

// Text always says the severity, so colour is never the only signal.
const STYLE: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-700 text-white",
  medium: "bg-amber-200 text-amber-950",
  low: "bg-slate-200 text-slate-800",
  unknown: "border border-dashed border-slate-400 text-slate-700",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex h-5 items-center rounded-full px-2 text-xs font-medium capitalize ${STYLE[severity]}`}
    >
      {severity}
    </span>
  );
}

export function formatRisk(risk: number | null): string {
  if (risk === null) return "Not scored";
  return risk >= 10 ? risk.toFixed(0) : risk.toFixed(risk >= 1 ? 1 : 2);
}

export function formatEpss(epss: number | null): string {
  if (epss === null) return "—";
  return `${(epss * 100).toFixed(epss < 0.01 ? 2 : 1)}%`;
}
