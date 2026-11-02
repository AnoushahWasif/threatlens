import { describe, expect, it } from "vitest";

import {
  countByStatus,
  EMPTY_THREAT,
  escapeMarkdown,
  exportFilename,
  groupByCategory,
  LIMITS,
  modelErrors,
  type Threat,
  threatErrors,
  type ThreatModel,
  threatModelSchema,
  toMarkdown,
} from "@/lib/threats";

let n = 0;
function threat(overrides: Partial<Threat> = {}): Threat {
  n += 1;
  return {
    id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    category: "spoofing",
    title: `Threat ${n}`,
    description: "An attacker does something.",
    mitigation: "Stop them.",
    component: "API",
    status: "accepted",
    source: "llm",
    edited: false,
    created_at: "2026-10-31T09:00:00.123456Z",
    updated_at: "2026-10-31T09:00:00+00:00",
    ...overrides,
  };
}

function model(threats: Threat[], overrides: Partial<ThreatModel> = {}): ThreatModel {
  return {
    id: "5d2c8b1e-7a4f-4c3d-9e6b-1f0a2d3c4b5e",
    name: "payments-service",
    architecture: "A FastAPI app behind an ALB talks to Stripe and Postgres.",
    threats,
    drafted_with: "claude-opus-5-5",
    drafted_at: "2026-10-31T09:00:00Z",
    created_at: "2026-10-31T08:00:00Z",
    ...overrides,
  };
}

describe("threatModelSchema", () => {
  it("accepts what the API sends, with either UTC spelling", () => {
    expect(threatModelSchema.safeParse(model([threat()])).success).toBe(true);
  });

  it.each([
    ["an unknown STRIDE category", { category: "phishing" }],
    ["an unknown status", { status: "approved" }],
    ["a title over the limit", { title: "x".repeat(LIMITS.title + 1) }],
    ["a non-UUID id", { id: "../../admin" }],
  ])("rejects %s", (_name, overrides) => {
    expect(threatModelSchema.safeParse(model([threat(overrides as Partial<Threat>)])).success).toBe(false);
  });

  it("rejects more threats than the API allows", () => {
    const many = Array.from({ length: LIMITS.threats + 1 }, () => threat());
    expect(threatModelSchema.safeParse(model(many)).success).toBe(false);
  });
});

describe("form checks", () => {
  it("wants a title and a description, after trimming", () => {
    const errors = threatErrors({ ...EMPTY_THREAT, title: "   ", description: "\n" });
    expect(Object.keys(errors).sort()).toEqual(["description", "title"]);
  });

  it("matches the API's length limits", () => {
    const ok = { ...EMPTY_THREAT, title: "x".repeat(LIMITS.title), description: "y" };
    expect(threatErrors(ok)).toEqual({});
    expect(threatErrors({ ...ok, title: ok.title + "x" }).title).toMatch(/under 120/);
    expect(threatErrors({ ...ok, mitigation: "m".repeat(LIMITS.mitigation + 1) }).mitigation).toBeDefined();
  });

  it("asks for enough architecture to draft from", () => {
    expect(modelErrors({ name: "x", architecture: "short" }).architecture).toMatch(/at least 40/);
    expect(modelErrors({ name: "x", architecture: "a".repeat(40) })).toEqual({});
    expect(modelErrors({ name: "", architecture: "a".repeat(8_001) })).toMatchObject({
      name: expect.any(String),
      architecture: expect.stringMatching(/under 8,000/),
    });
  });
});

describe("counting and grouping", () => {
  it("counts every status, zeros included", () => {
    expect(countByStatus([threat(), threat({ status: "draft" })])).toEqual({
      draft: 1,
      accepted: 1,
      rejected: 0,
    });
  });

  it("groups in STRIDE order and skips empty categories", () => {
    const groups = groupByCategory([
      threat({ category: "elevation_of_privilege" }),
      threat({ category: "spoofing" }),
      threat({ category: "elevation_of_privilege" }),
    ]);
    expect(groups.map(([c, list]) => [c, list.length])).toEqual([
      ["spoofing", 1],
      ["elevation_of_privilege", 2],
    ]);
  });
});

describe("escapeMarkdown", () => {
  it.each([
    ["<img src=x onerror=alert(1)>", "\\<img src=x onerror=alert(1)\\>"],
    ["[click](javascript:alert(1))", "\\[click\\](javascript:alert(1))"],
    ["![x](https://evil.example/t.png)", "\\!\\[x\\](https://evil.example/t.png)"],
    ["a | b", "a \\| b"],
    ["`code` and *bold* and _em_", "\\`code\\` and \\*bold\\* and \\_em\\_"],
    ["# heading", "\\# heading"],
    ["- item", "\\- item"],
    ["1. item", "\\1. item"],
    ["back\\slash", "back\\\\slash"],
  ])("escapes %j", (input, expected) => {
    expect(escapeMarkdown(input)).toBe(expected);
  });

  it("keeps line breaks as hard breaks, so a line can't start a new block", () => {
    expect(escapeMarkdown("one\r\n\r\n# two")).toBe("one  \n\\# two");
  });

  it("leaves ordinary text alone", () => {
    expect(escapeMarkdown("Rate limit per IP, 10 req/s.")).toBe("Rate limit per IP, 10 req/s.");
  });
});

describe("toMarkdown", () => {
  const at = new Date("2026-11-02T12:00:00Z");

  it("exports accepted threats only, grouped by category, and says what was left out", () => {
    const md = toMarkdown(
      model([
        threat({ title: "Kept", category: "tampering" }),
        threat({ title: "Not reviewed", status: "draft" }),
        threat({ title: "Thrown out", status: "rejected" }),
        threat({ title: "Mine", source: "manual", mitigation: "" }),
      ]),
      at,
    );
    expect(md).toContain("# Threat model: payments-service"); // a mid-word hyphen needs no escape
    expect(md).toContain("Exported 2026-11-02 from ThreatLens. 2 accepted threats.");
    expect(md).toContain("> 1 drafted threats haven't been reviewed and are not included.");
    expect(md).not.toContain("Not reviewed");
    expect(md).not.toContain("Thrown out");
    expect(md.indexOf("## Spoofing")).toBeLessThan(md.indexOf("## Tampering"));
    expect(md).toContain("**Mitigation:** _none yet_");
    expect(md).toContain("**Source:** written by hand");
  });

  it("says so when nothing is accepted", () => {
    expect(toMarkdown(model([threat({ status: "draft" })]), at)).toContain("_No threats accepted yet._");
  });

  it("escapes every piece of user or AI text", () => {
    const evil = "<script>alert(1)</script>";
    const md = toMarkdown(
      model([threat({ title: evil, description: evil, mitigation: evil, component: evil })], {
        name: evil,
        architecture: evil,
      }),
      at,
    );
    expect(md).not.toContain("<script>");
    expect(md.match(/\\<script\\>/g)).toHaveLength(6);
  });
});

describe("exportFilename", () => {
  it.each([
    ["payments-service", "payments-service-threat-model.md"],
    ["Payments Service (v2)", "payments-service-v2-threat-model.md"],
    ["../../etc/passwd", "etc-passwd-threat-model.md"],
    ["Café ünïcode", "cafe-unicode-threat-model.md"],
    ["日本語", "threat-model-threat-model.md"],
    ["a".repeat(200), `${"a".repeat(60)}-threat-model.md`],
  ])("%j → %j", (name, expected) => {
    expect(exportFilename(name)).toBe(expected);
  });
});
