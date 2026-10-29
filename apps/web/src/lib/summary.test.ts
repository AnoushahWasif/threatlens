import { describe, expect, it } from "vitest";

import { type Finding, SAMPLE_FINDINGS, SEVERITIES } from "@/lib/findings";
import { countBySeverity, packageRisks, summarize } from "@/lib/summary";

let n = 0;
function finding(
  overrides: Partial<Finding> & { name?: string; version?: string; ecosystem?: "npm" | "PyPI" } = {},
): Finding {
  const { name = "pkg", version = "1.0.0", ecosystem = "npm", ...rest } = overrides;
  n += 1;
  return {
    id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    project_id: "3f6c2a1e-8d4b-4c7a-9e21-5b0d7f3a9c11",
    dependency: { name, version, ecosystem, direct: true },
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

describe("countBySeverity", () => {
  it("lists every severity in order, zeros included", () => {
    const rows = countBySeverity([finding({ severity: "high" })]);
    expect(rows.map((r) => r.severity)).toEqual([...SEVERITIES]);
    expect(rows.find((r) => r.severity === "high")).toEqual({ severity: "high", count: 1, kev: 0 });
    expect(rows.filter((r) => r.count === 0)).toHaveLength(4);
  });

  it("counts KEV findings within each severity", () => {
    const rows = countBySeverity([
      finding({ severity: "critical", in_kev: true }),
      finding({ severity: "critical" }),
      finding({ severity: "low", in_kev: true }),
    ]);
    expect(rows[0]).toEqual({ severity: "critical", count: 2, kev: 1 });
    expect(rows[3]).toEqual({ severity: "low", count: 1, kev: 1 });
  });

  it("handles an empty list", () => {
    expect(countBySeverity([]).every((r) => r.count === 0 && r.kev === 0)).toBe(true);
  });
});

describe("packageRisks", () => {
  it("groups findings per package and keeps the highest risk", () => {
    const [row] = packageRisks([
      finding({ name: "lodash", risk_score: 16 }),
      finding({ name: "lodash", risk_score: 3 }),
      finding({ name: "lodash", risk_score: null }),
    ]);
    expect(row).toMatchObject({ name: "lodash", findings: 3, maxRisk: 16, inKev: false });
  });

  it("keeps two versions, or the same name in two ecosystems, apart", () => {
    const rows = packageRisks([
      finding({ name: "requests", version: "2.19.0", ecosystem: "PyPI" }),
      finding({ name: "requests", version: "2.31.0", ecosystem: "PyPI" }),
      finding({ name: "requests", version: "2.19.0", ecosystem: "npm" }),
    ]);
    expect(rows).toHaveLength(3);
  });

  it("marks a package in KEV if any of its findings is", () => {
    const [row] = packageRisks([finding({ name: "a" }), finding({ name: "a", in_kev: true })]);
    expect(row!.inKev).toBe(true);
  });

  it("sorts unscored packages after scored ones, even after a score of 0", () => {
    const rows = packageRisks([
      finding({ name: "unscored", risk_score: null }),
      finding({ name: "zero", risk_score: 0 }),
      finding({ name: "high", risk_score: 80 }),
    ]);
    expect(rows.map((r) => r.name)).toEqual(["high", "zero", "unscored"]);
    expect(rows[1]!.maxRisk).toBe(0);
    expect(rows[2]!.maxRisk).toBeNull();
  });

  it("breaks risk ties by number of findings, then by name, so the order is stable", () => {
    const rows = packageRisks([
      finding({ name: "b", risk_score: 10 }),
      finding({ name: "a", risk_score: 10 }),
      finding({ name: "c", risk_score: 10 }),
      finding({ name: "c", risk_score: 1 }),
    ]);
    expect(rows.map((r) => r.name)).toEqual(["c", "a", "b"]);
  });
});

describe("summarize", () => {
  it("adds up the sample scan", () => {
    const s = summarize(SAMPLE_FINDINGS);
    expect(s).toMatchObject({ total: 4, kev: 1, unscored: 1, packages: 4, unscoredPackages: 1 });
    expect(s.topPackages.map((p) => p.name)).toEqual(["log4j-core", "lodash", "jinja2"]);
  });

  it("caps the chart at the top N scored packages", () => {
    const many = Array.from({ length: 30 }, (_, i) => finding({ name: `p${i}`, risk_score: i }));
    const s = summarize(many, 8);
    expect(s.topPackages).toHaveLength(8);
    expect(s.topPackages[0]!.maxRisk).toBe(29);
    expect(s.packages).toBe(30);
  });

  it("leaves every package out of the chart when nothing is scored", () => {
    const s = summarize([finding({ risk_score: null }), finding({ name: "x", risk_score: null })]);
    expect(s.topPackages).toEqual([]);
    expect(s.unscoredPackages).toBe(2);
    expect(s.unscored).toBe(2);
  });

  it("is all zeros for no findings", () => {
    expect(summarize([])).toMatchObject({ total: 0, kev: 0, unscored: 0, packages: 0, topPackages: [] });
  });
});
