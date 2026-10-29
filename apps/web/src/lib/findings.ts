import { z } from "zod";

// Mirrors `Finding` and `Dependency` in apps/api/src/threatlens_api/models.py, including the
// id and name patterns, so a malformed id can never end up in a link.
const VULN_ID = /^[A-Z][A-Z0-9]*-[A-Za-z0-9\-:.]{1,60}$/;
const vulnId = z.string().max(64).regex(VULN_ID);
const version = z.string().min(1).max(128).regex(/^[A-Za-z0-9._\-+~^:]+$/);

export const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const findingSchema = z.object({
  id: z.uuid(),
  project_id: z.uuid(),
  dependency: z.object({
    name: z.string().min(1).max(214).regex(/^[A-Za-z0-9@][A-Za-z0-9._\-/:@]*$/),
    version,
    ecosystem: z.enum(["PyPI", "npm", "Maven", "Go", "crates.io", "NuGet"]),
    direct: z.boolean(),
  }),
  vuln_id: vulnId,
  aliases: z.array(vulnId).max(50),
  summary: z.string().max(1_000),
  severity: z.enum(SEVERITIES),
  cvss_score: z.number().min(0).max(10).nullable(),
  epss: z.number().min(0).max(1).nullable(),
  in_kev: z.boolean(),
  risk_score: z.number().min(0).max(100).nullable(),
  fixed_versions: z.array(version).max(50),
});

export const MAX_FINDINGS = 20_000;
export const findingListSchema = z.array(findingSchema).max(MAX_FINDINGS);

export type Finding = z.infer<typeof findingSchema>;

// Same weights as risk.py; used to break ties and to order unscored findings.
const WEIGHT: Record<Severity, number> = {
  critical: 1,
  high: 0.75,
  medium: 0.5,
  low: 0.25,
  unknown: 0.5,
};
const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

export type SortKey = "risk" | "severity" | "epss" | "package";
export type Sort = { key: SortKey; direction: "asc" | "desc" };
export const DEFAULT_SORT: Sort = { key: "risk", direction: "desc" };

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** The API's own ranking: highest risk first, unscored after every scored finding. */
function apiOrder(a: Finding, b: Finding): number {
  const unscored = Number(a.risk_score === null) - Number(b.risk_score === null);
  if (unscored) return unscored;
  return (
    (b.risk_score ?? 0) - (a.risk_score ?? 0) ||
    WEIGHT[b.severity] - WEIGHT[a.severity] ||
    byText(a.dependency.name, b.dependency.name) ||
    byText(a.vuln_id, b.vuln_id)
  );
}

/**
 * Missing values (no risk score, no EPSS) always go last, whichever way the column is
 * sorted: "no data" must never float to the top of an ascending list and look like "safest".
 */
export function sortFindings(findings: readonly Finding[], sort: Sort = DEFAULT_SORT): Finding[] {
  const flip = sort.direction === "asc" ? -1 : 1;
  const nullable = (a: number | null, b: number | null) => {
    if (a === null || b === null) return Number(a === null) - Number(b === null);
    return flip * (b - a);
  };
  const compare: Record<SortKey, (a: Finding, b: Finding) => number> = {
    risk: (a, b) => nullable(a.risk_score, b.risk_score),
    epss: (a, b) => nullable(a.epss, b.epss),
    severity: (a, b) => flip * (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
    package: (a, b) => -flip * byText(a.dependency.name, b.dependency.name),
  };
  return [...findings].sort((a, b) => compare[sort.key](a, b) || apiOrder(a, b));
}

export type Filter = { severities: ReadonlySet<Severity>; kevOnly: boolean; query: string };
export const NO_FILTER: Filter = { severities: new Set(), kevOnly: false, query: "" };
export const MAX_QUERY_LENGTH = 100;

export function filterFindings(findings: readonly Finding[], filter: Filter): Finding[] {
  const query = filter.query.trim().slice(0, MAX_QUERY_LENGTH).toLowerCase();
  return findings.filter(
    (f) =>
      (filter.severities.size === 0 || filter.severities.has(f.severity)) &&
      (!filter.kevOnly || f.in_kev) &&
      (!query ||
        f.dependency.name.toLowerCase().includes(query) ||
        f.vuln_id.toLowerCase().includes(query) ||
        f.aliases.some((a) => a.toLowerCase().includes(query))),
  );
}

export function advisoryLinks(finding: Finding): { label: string; href: string }[] {
  const ids = [finding.vuln_id, ...finding.aliases];
  const links = [
    {
      label: "OSV.dev",
      href: `https://osv.dev/vulnerability/${encodeURIComponent(finding.vuln_id)}`,
    },
  ];
  const cve = ids.find((id) => /^CVE-\d{4}-\d{4,}$/.test(id));
  if (cve) {
    links.push({ label: "NVD", href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}` });
  }
  return links;
}

const SAMPLE_PROJECT = "3f6c2a1e-8d4b-4c7a-9e21-5b0d7f3a9c11"; // payments-service

// Numbers from a real scan on 28 Oct 2026 (see docs/ARCHITECTURE.md, "Risk score").
export const SAMPLE_FINDINGS: Finding[] = [
  {
    id: "5d1e7c3a-2b4f-4a8e-9c6d-1f0e2a3b4c51",
    project_id: SAMPLE_PROJECT,
    dependency: { name: "jinja2", version: "2.10", ecosystem: "PyPI", direct: true },
    vuln_id: "GHSA-462w-v97r-4m45",
    aliases: ["CVE-2019-10906", "PYSEC-2019-217"],
    summary: "Jinja2 sandbox escape via string formatting",
    severity: "medium",
    cvss_score: null,
    epss: 0.00892,
    in_kev: false,
    risk_score: 0.446,
    fixed_versions: ["2.10.1"],
  },
  {
    id: "8a2c4e6f-1d3b-4f5a-8c7e-9b0d1e2f3a62",
    project_id: SAMPLE_PROJECT,
    dependency: { name: "log4j-core", version: "2.14.1", ecosystem: "Maven", direct: false },
    vuln_id: "GHSA-jfh8-c2jp-5v3q",
    aliases: ["CVE-2021-44228"],
    summary: "Remote code injection in Log4j (Log4Shell)",
    severity: "critical",
    cvss_score: 10,
    epss: 0.94358,
    in_kev: true,
    risk_score: 100,
    fixed_versions: ["2.15.0", "2.12.2"],
  },
  {
    id: "b3d5f7a9-2c4e-4b6d-9f8a-0c1e2d3f4a73",
    project_id: SAMPLE_PROJECT,
    dependency: { name: "lodash", version: "4.17.15", ecosystem: "npm", direct: true },
    vuln_id: "GHSA-35jh-r3h4-6jhm",
    aliases: ["CVE-2021-23337"],
    summary: "Command injection in lodash template",
    severity: "high",
    cvss_score: 7.2,
    epss: 0.213,
    in_kev: false,
    risk_score: 16,
    fixed_versions: ["4.17.21"],
  },
  {
    id: "c4e6a8b0-3d5f-4c7e-8a9b-1d2e3f4a5b84",
    project_id: SAMPLE_PROJECT,
    dependency: { name: "pyyaml", version: "5.3", ecosystem: "PyPI", direct: true },
    vuln_id: "PYSEC-2021-142",
    aliases: ["CVE-2020-14343"],
    // Unscored on purpose, to show the state: the EPSS lookup failed for this scan.
    summary: "Arbitrary code execution when loading untrusted YAML with full_load",
    severity: "unknown",
    cvss_score: null,
    epss: null,
    in_kev: false,
    risk_score: null,
    fixed_versions: ["5.4"],
  },
];

export function sampleFindings(projectId: string): Finding[] | null {
  return projectId === SAMPLE_PROJECT ? SAMPLE_FINDINGS : null;
}
