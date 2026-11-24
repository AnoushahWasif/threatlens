import { z } from "zod";

import { ApiError } from "@/lib/api-error";

// Mirrors `Scan` in apps/api/src/threatlens_api/scans.py, limits included.
export const MAX_UPLOAD_BYTES = 1_000_000;
const FILENAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

const count = z.number().int().min(0);

export const scanSchema = z.object({
  id: z.uuid(),
  project_id: z.uuid(),
  filename: z.string().regex(FILENAME),
  format: z.string().max(40),
  status: z.enum(["queued", "running", "done", "failed"]),
  dependencies: count,
  skipped: count,
  skipped_examples: z
    .array(z.object({ ref: z.string().max(120), reason: z.string().max(200) }))
    .max(20),
  findings: count,
  unchecked: count,
  epss_failed: count,
  kev_available: z.boolean(),
  kev_stale: z.boolean(),
  // Written by the worker for the user (fixed messages and parser reasons), up to 200 chars.
  error: z.string().max(200).nullable(),
});

export type Scan = z.infer<typeof scanSchema>;

export const FINISHED: ReadonlySet<Scan["status"]> = new Set(["done", "failed"]);

/**
 * The API takes names like `requirements-dev.txt` and picks the parser from them, so the
 * meaningful end is kept and anything else (spaces, brackets, accents) becomes "-".
 * `requirements (1).txt` -> `requirements--1-.txt`. Null if nothing usable is left.
 */
export function uploadName(name: string): string | null {
  const base = name.split(/[\\/]/).pop() ?? "";
  let safe = base.replace(/[^A-Za-z0-9._-]/g, "-").replace(/^[^A-Za-z0-9]+/, "");
  if (safe.length > 100) safe = safe.slice(safe.length - 100).replace(/^[^A-Za-z0-9]+/, "");
  return FILENAME.test(safe) ? safe : null;
}

/** Checks that need no server: a fixed message, or null if the file can be sent. */
export function fileProblem(file: { name: string; size: number }): string | null {
  if (file.size === 0) return "That file is empty.";
  if (file.size > MAX_UPLOAD_BYTES) return "That file is over 1 MB, the most ThreatLens takes.";
  if (uploadName(file.name) === null) return "That file name can't be used. Rename it and try again.";
  return null;
}

const SUPPORTED =
  "a CycloneDX JSON SBOM, requirements.txt, package-lock.json, pnpm-lock.yaml, uv.lock or poetry.lock";

/** Fixed text per refusal; nothing from the server's error body is shown. */
export function uploadErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) return "Something went wrong while uploading. Try again.";
  if (error.kind !== "http") return error.message;
  switch (error.code) {
    case "bad_file":
      return `ThreatLens couldn't read that file. Upload ${SUPPORTED}, unchanged.`;
    case "scan_limit": {
      const minutes = error.retryAfter === undefined ? null : Math.max(1, Math.ceil(error.retryAfter / 60));
      return minutes === null
        ? "That's the most scans for this hour. Try again later."
        : `That's the most scans for this hour. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`;
    }
    case "payload_too_large":
      return "That file is over 1 MB, the most ThreatLens takes.";
    case "queue_unavailable":
    case "storage_unavailable":
      return "Scans can't start right now. Try again in a few minutes.";
    default:
      return error.message;
  }
}

export type Outcome = { tone: "good" | "warning" | "bad"; text: string };

/** One line about a finished scan. */
export function scanOutcome(scan: Scan): Outcome {
  if (scan.status === "failed") {
    return { tone: "bad", text: scan.error ?? "The scan failed. Try again." };
  }
  const plural = (n: number, word: string) => `${n.toLocaleString("en")} ${word}${n === 1 ? "" : "s"}`;
  const found = `${plural(scan.findings, "finding")} in ${plural(scan.dependencies, "package")}`;
  const gaps: string[] = [];
  if (scan.unchecked > 0) gaps.push(`${plural(scan.unchecked, "package")} couldn't be checked`);
  if (scan.epss_failed > 0) gaps.push(`${scan.epss_failed.toLocaleString("en")} without an EPSS score`);
  if (!scan.kev_available) gaps.push("the CISA KEV list couldn't be loaded");
  else if (scan.kev_stale) gaps.push("the CISA KEV list was out of date");
  // A partial scan must not read as a clean one.
  if (gaps.length > 0) return { tone: "warning", text: `${found}, but ${gaps.join("; ")}.` };
  return { tone: "good", text: `${found}.` };
}

/** How long to wait before asking again: every 2 s for the first minute, then every 5 s. */
export function pollDelay(elapsedMs: number): number {
  return elapsedMs < 60_000 ? 2_000 : 5_000;
}

/** Stop following after this; the scan carries on and the page can be reloaded later. */
export const MAX_FOLLOW_MS = 15 * 60_000;
