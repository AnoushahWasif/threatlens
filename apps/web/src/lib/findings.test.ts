import { describe, expect, it } from "vitest";

import {
  advisoryLinks,
  filterFindings,
  type Finding,
  findingListSchema,
  findingSchema,
  MAX_QUERY_LENGTH,
  NO_FILTER,
  SAMPLE_FINDINGS,
  sortFindings,
} from "@/lib/findings";

let n = 0;
function finding(overrides: Partial<Finding> & { name?: string } = {}): Finding {
  const { name = "pkg", ...rest } = overrides;
  n += 1;
  return {
    id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    project_id: "3f6c2a1e-8d4b-4c7a-9e21-5b0d7f3a9c11",
    dependency: { name, version: "1.0.0", ecosystem: "npm", direct: true },
    vuln_id: `GHSA-test-${n}`,
    aliases: [],
    summary: "",
    severity: "medium",
    cvss_score: null,
    epss: 0.1,
    in_kev: false,
    risk_score: 5,
    fixed_versions: [],
    ...rest,
  };
}

const names = (list: Finding[]) => list.map((f) => f.dependency.name);

describe("findingSchema", () => {
  it("accepts the sample findings", () => {
    expect(findingListSchema.safeParse(SAMPLE_FINDINGS).success).toBe(true);
  });

  it.each([
    ["javascript:alert(1)"],
    ["../../admin"],
    ["GHSA-<script>"],
    ["cve-2021-1234"],
    ["A".repeat(65)],
  ])("rejects vulnerability id %s, so it can never reach a link", (vuln_id) => {
    expect(findingSchema.safeParse({ ...finding(), vuln_id }).success).toBe(false);
  });

  it.each([
    { risk_score: 101 },
    { risk_score: -1 },
    { epss: 1.5 },
    { epss: Number.NaN },
    { cvss_score: 11 },
    { severity: "catastrophic" },
    { aliases: Array.from({ length: 51 }, (_, i) => `CVE-2020-${1000 + i}`) },
    { dependency: { name: "x y", version: "1", ecosystem: "npm", direct: true } },
    { dependency: { name: "x", version: "1", ecosystem: "Gradle", direct: true } },
  ])("rejects out-of-range or unknown values: %o", (overrides) => {
    expect(findingSchema.safeParse({ ...finding(), ...overrides }).success).toBe(false);
  });

  it("keeps a null risk score (unscored is a real state)", () => {
    expect(findingSchema.parse({ ...finding(), risk_score: null, epss: null }).risk_score).toBeNull();
  });
});

describe("sortFindings", () => {
  const list = [
    finding({ name: "medium-low-risk", risk_score: 2, severity: "medium" }),
    finding({ name: "unscored-critical", risk_score: null, epss: null, severity: "critical" }),
    finding({ name: "kev", risk_score: 100, severity: "critical", in_kev: true }),
    finding({ name: "unscored-low", risk_score: null, epss: null, severity: "low" }),
    finding({ name: "high", risk_score: 16, severity: "high" }),
  ];

  it("defaults to the API's ranking: risk first, unscored last by severity", () => {
    expect(names(sortFindings(list))).toEqual([
      "kev",
      "high",
      "medium-low-risk",
      "unscored-critical",
      "unscored-low",
    ]);
  });

  it("keeps unscored findings last even when sorting risk ascending", () => {
    const sorted = names(sortFindings(list, { key: "risk", direction: "asc" }));
    expect(sorted.slice(0, 3)).toEqual(["medium-low-risk", "high", "kev"]);
    expect(sorted.slice(3)).toEqual(["unscored-critical", "unscored-low"]);
  });

  it("keeps missing EPSS last in both directions", () => {
    for (const direction of ["asc", "desc"] as const) {
      const sorted = sortFindings(list, { key: "epss", direction });
      expect(sorted.slice(-2).every((f) => f.epss === null)).toBe(true);
    }
  });

  it("sorts severity worst first, unknown last", () => {
    const sorted = sortFindings(list, { key: "severity", direction: "desc" });
    expect(sorted.map((f) => f.severity)).toEqual(["critical", "critical", "high", "medium", "low"]);
  });

  it("sorts package names A to Z", () => {
    const sorted = names(sortFindings(list, { key: "package", direction: "asc" }));
    expect(sorted).toEqual([...sorted].sort());
  });

  it("breaks ties the same way every time and doesn't touch the input", () => {
    const same = [finding({ name: "b" }), finding({ name: "a" }), finding({ name: "c" })];
    const before = [...same];
    const once = sortFindings(same, { key: "severity", direction: "desc" });
    expect(names(once)).toEqual(["a", "b", "c"]);
    expect(names(sortFindings([...same].reverse(), { key: "severity", direction: "desc" }))).toEqual(
      names(once),
    );
    expect(same).toEqual(before);
  });

  it("handles an empty list", () => {
    expect(sortFindings([])).toEqual([]);
  });
});

describe("filterFindings", () => {
  const list = [
    finding({ name: "lodash", severity: "high", aliases: ["CVE-2021-23337"] }),
    finding({ name: "log4j-core", severity: "critical", in_kev: true }),
    finding({ name: "jinja2", severity: "medium" }),
  ];

  it("returns everything with no filter", () => {
    expect(filterFindings(list, NO_FILTER)).toHaveLength(3);
  });

  it("filters by any of the chosen severities", () => {
    const severities = new Set(["high", "critical"] as const);
    expect(names(filterFindings(list, { ...NO_FILTER, severities }))).toEqual(["lodash", "log4j-core"]);
  });

  it("filters to known-exploited only", () => {
    expect(names(filterFindings(list, { ...NO_FILTER, kevOnly: true }))).toEqual(["log4j-core"]);
  });

  it.each(["LODASH", "  lodash ", "cve-2021-23337", "23337"])("finds lodash by %j", (query) => {
    expect(names(filterFindings(list, { ...NO_FILTER, query }))).toEqual(["lodash"]);
  });

  it("combines filters with AND", () => {
    const filter = { severities: new Set(["high"] as const), kevOnly: true, query: "" };
    expect(filterFindings(list, filter)).toEqual([]);
  });

  it("treats regex characters as plain text", () => {
    expect(filterFindings(list, { ...NO_FILTER, query: ".*" })).toEqual([]);
  });

  it("caps the query length", () => {
    const query = "lodash" + "x".repeat(MAX_QUERY_LENGTH);
    expect(filterFindings(list, { ...NO_FILTER, query })).toEqual([]);
  });
});

describe("advisoryLinks", () => {
  it("links OSV always and NVD when there is a CVE", () => {
    const links = advisoryLinks(finding({ vuln_id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"] }));
    expect(links.map((l) => l.href)).toEqual([
      "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
    ]);
  });

  it("has no NVD link without a CVE", () => {
    expect(advisoryLinks(finding({ vuln_id: "PYSEC-2021-142" }))).toHaveLength(1);
  });

  it("encodes the id in the path", () => {
    const [osv] = advisoryLinks(finding({ vuln_id: "GO-2024-1:2" }));
    expect(osv.href).toBe("https://osv.dev/vulnerability/GO-2024-1%3A2");
  });
});
