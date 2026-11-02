import { z } from "zod";

// Mirrors apps/api/src/threatlens_api/threats.py, limits included.
export const STRIDE = [
  "spoofing",
  "tampering",
  "repudiation",
  "information_disclosure",
  "denial_of_service",
  "elevation_of_privilege",
] as const;
export type Stride = (typeof STRIDE)[number];

export const STRIDE_LABELS: Record<Stride, string> = {
  spoofing: "Spoofing",
  tampering: "Tampering",
  repudiation: "Repudiation",
  information_disclosure: "Information disclosure",
  denial_of_service: "Denial of service",
  elevation_of_privilege: "Elevation of privilege",
};

export const STATUSES = ["draft", "accepted", "rejected"] as const;
export type ThreatStatus = (typeof STATUSES)[number];

export const LIMITS = {
  name: 100,
  architectureMin: 40,
  architecture: 8_000,
  title: 120,
  description: 1_000,
  mitigation: 1_000,
  component: 100,
  threats: 100,
} as const;

const timestamp = z.iso.datetime({ offset: true });

export const threatSchema = z.object({
  id: z.uuid(),
  category: z.enum(STRIDE),
  title: z.string().min(1).max(LIMITS.title),
  description: z.string().min(1).max(LIMITS.description),
  mitigation: z.string().max(LIMITS.mitigation),
  component: z.string().max(LIMITS.component),
  status: z.enum(STATUSES),
  source: z.enum(["llm", "manual"]),
  edited: z.boolean(),
  created_at: timestamp,
  updated_at: timestamp,
});

export const threatModelSchema = z.object({
  id: z.uuid(),
  name: z.string().min(1).max(LIMITS.name),
  architecture: z.string().max(LIMITS.architecture),
  threats: z.array(threatSchema).max(LIMITS.threats),
  drafted_with: z.string().max(64).nullable(),
  drafted_at: timestamp.nullable(),
  created_at: timestamp,
});

export const draftResultSchema = z.object({
  model: threatModelSchema,
  added: z.number().int().min(0).max(LIMITS.threats),
  dropped: z.number().int().min(0),
});

export type Threat = z.infer<typeof threatSchema>;
export type DraftResult = z.infer<typeof draftResultSchema>;
export type ThreatModel = z.infer<typeof threatModelSchema>;

/** What a person types into the threat form; the API sets status, source and ids. */
export type ThreatInput = Pick<Threat, "category" | "title" | "description" | "mitigation" | "component">;
export type ThreatPatch = Partial<ThreatInput> & { status?: ThreatStatus };
export type ModelInput = { name: string; architecture: string };

export const EMPTY_THREAT: ThreatInput = {
  category: "spoofing",
  title: "",
  description: "",
  mitigation: "",
  component: "",
};

type Errors<T> = Partial<Record<keyof T, string>>;

/** Same rules as the API, checked first so a typo doesn't cost a round trip. */
export function threatErrors(input: ThreatInput): Errors<ThreatInput> {
  const errors: Errors<ThreatInput> = {};
  const title = input.title.trim();
  const description = input.description.trim();
  if (!title) errors.title = "Give the threat a title.";
  else if (title.length > LIMITS.title) errors.title = `Keep it under ${LIMITS.title} characters.`;
  if (!description) errors.description = "Say how an attacker would do it.";
  else if (description.length > LIMITS.description)
    errors.description = `Keep it under ${LIMITS.description} characters.`;
  if (input.mitigation.trim().length > LIMITS.mitigation)
    errors.mitigation = `Keep it under ${LIMITS.mitigation} characters.`;
  if (input.component.trim().length > LIMITS.component)
    errors.component = `Keep it under ${LIMITS.component} characters.`;
  return errors;
}

export function modelErrors(input: ModelInput): Errors<ModelInput> {
  const errors: Errors<ModelInput> = {};
  const name = input.name.trim();
  const architecture = input.architecture.trim();
  if (!name) errors.name = "Give the model a name.";
  else if (name.length > LIMITS.name) errors.name = `Keep it under ${LIMITS.name} characters.`;
  if (architecture.length < LIMITS.architectureMin)
    errors.architecture = `Describe the system in at least ${LIMITS.architectureMin} characters: what talks to what, and where data is stored.`;
  else if (architecture.length > LIMITS.architecture)
    errors.architecture = `Keep it under ${LIMITS.architecture.toLocaleString("en")} characters.`;
  return errors;
}

export const trimThreat = (input: ThreatInput): ThreatInput => ({
  category: input.category,
  title: input.title.trim(),
  description: input.description.trim(),
  mitigation: input.mitigation.trim(),
  component: input.component.trim(),
});

export function countByStatus(threats: readonly Threat[]): Record<ThreatStatus, number> {
  const counts = { draft: 0, accepted: 0, rejected: 0 };
  for (const t of threats) counts[t.status] += 1;
  return counts;
}

/** Threats in STRIDE order; within a category, the API's order (oldest first). */
export function groupByCategory(threats: readonly Threat[]): [Stride, Threat[]][] {
  return STRIDE.map((c) => [c, threats.filter((t) => t.category === c)] as [Stride, Threat[]]).filter(
    ([, list]) => list.length > 0,
  );
}

// Threat text comes from a person or an LLM that read user input. Escaped, it can't add
// links, images, HTML or table breaks when the exported file is rendered.
export function escapeMarkdown(text: string): string {
  return text
    .replace(/\r\n?/g, "\n")
    .replace(/[\\`*_[\]<>|~!]/g, "\\$&")
    .replace(/^(\s*)([#>+=-]|\d+[.)])/gm, "$1\\$2")
    .replace(/\n{2,}/g, "\n")
    .split("\n")
    .join("  \n");
}

export function toMarkdown(model: ThreatModel, exportedAt: Date = new Date()): string {
  const counts = countByStatus(model.threats);
  const accepted = model.threats.filter((t) => t.status === "accepted");
  const lines = [
    `# Threat model: ${escapeMarkdown(model.name)}`,
    "",
    `Exported ${exportedAt.toISOString().slice(0, 10)} from ThreatLens. ${accepted.length} accepted threats.`,
  ];
  if (counts.draft > 0) {
    lines.push("", `> ${counts.draft} drafted threats haven't been reviewed and are not included.`);
  }
  lines.push("", "## Architecture", "", escapeMarkdown(model.architecture));

  for (const [category, threats] of groupByCategory(accepted)) {
    lines.push("", `## ${STRIDE_LABELS[category]}`);
    for (const t of threats) {
      lines.push("", `### ${escapeMarkdown(t.title)}`, "");
      if (t.component) lines.push(`**Component:** ${escapeMarkdown(t.component)}  `);
      lines.push(`**Threat:** ${escapeMarkdown(t.description)}  `);
      lines.push(`**Mitigation:** ${t.mitigation ? escapeMarkdown(t.mitigation) : "_none yet_"}  `);
      lines.push(`**Source:** ${t.source === "llm" ? (t.edited ? "AI draft, edited" : "AI draft") : "written by hand"}`);
    }
  }
  if (accepted.length === 0) lines.push("", "_No threats accepted yet._");
  return lines.join("\n") + "\n";
}

export function exportFilename(name: string): string {
  const slug = name
    .normalize("NFKD")
    .replace(/\p{M}/gu, "") // accents split off by NFKD, so "Café" becomes "cafe"
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60)
    .replace(/-+$/, "");
  return `${slug || "threat-model"}-threat-model.md`;
}
