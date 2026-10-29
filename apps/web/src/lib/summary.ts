import { type Finding, SEVERITIES, type Severity } from "@/lib/findings";

export type SeverityCount = { severity: Severity; count: number; kev: number };

export type PackageRisk = {
  key: string;
  name: string;
  version: string;
  ecosystem: Finding["dependency"]["ecosystem"];
  findings: number;
  /** Highest risk among this package's findings; null when none of them could be scored. */
  maxRisk: number | null;
  inKev: boolean;
};

export type Summary = {
  total: number;
  kev: number;
  unscored: number;
  packages: number;
  bySeverity: SeverityCount[];
  topPackages: PackageRisk[];
  /** Packages left out of the chart because none of their findings has a score. */
  unscoredPackages: number;
};

export const TOP_PACKAGES = 8;

/** Every severity is listed, in severity order, even at zero, so the axis never shifts. */
export function countBySeverity(findings: readonly Finding[]): SeverityCount[] {
  const counts = new Map(SEVERITIES.map((s) => [s, { severity: s, count: 0, kev: 0 }]));
  for (const f of findings) {
    const row = counts.get(f.severity)!;
    row.count += 1;
    if (f.in_kev) row.kev += 1;
  }
  return [...counts.values()];
}

export function packageRisks(findings: readonly Finding[]): PackageRisk[] {
  const byPackage = new Map<string, PackageRisk>();
  for (const f of findings) {
    const { name, version, ecosystem } = f.dependency;
    // Two versions of one package are separate fixes, so they count separately.
    const key = `${ecosystem}:${name}@${version}`;
    const row = byPackage.get(key) ?? {
      key,
      name,
      version,
      ecosystem,
      findings: 0,
      maxRisk: null,
      inKev: false,
    };
    row.findings += 1;
    row.inKev ||= f.in_kev;
    if (f.risk_score !== null) row.maxRisk = Math.max(row.maxRisk ?? 0, f.risk_score);
    byPackage.set(key, row);
  }
  // Unscored last: missing data is not the same as low risk, so it never sorts as zero.
  return [...byPackage.values()].sort(
    (a, b) =>
      Number(a.maxRisk === null) - Number(b.maxRisk === null) ||
      (b.maxRisk ?? 0) - (a.maxRisk ?? 0) ||
      b.findings - a.findings ||
      (a.key < b.key ? -1 : 1),
  );
}

export function summarize(findings: readonly Finding[], top = TOP_PACKAGES): Summary {
  const packages = packageRisks(findings);
  const scored = packages.filter((p) => p.maxRisk !== null);
  return {
    total: findings.length,
    kev: findings.filter((f) => f.in_kev).length,
    unscored: findings.filter((f) => f.risk_score === null).length,
    packages: packages.length,
    bySeverity: countBySeverity(findings),
    topPackages: scored.slice(0, top),
    unscoredPackages: packages.length - scored.length,
  };
}
