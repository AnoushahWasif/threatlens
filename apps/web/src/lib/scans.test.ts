import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api-error";
import {
  fileProblem,
  MAX_UPLOAD_BYTES,
  pollDelay,
  scanOutcome,
  scanSchema,
  uploadErrorMessage,
  uploadName,
} from "@/lib/scans";
import { SCAN } from "@/lib/scan-fixture";

describe("uploadName", () => {
  it.each([
    ["requirements.txt", "requirements.txt"],
    ["requirements (1).txt", "requirements--1-.txt"],
    ["C:\\Users\\me\\package-lock.json", "package-lock.json"],
    ["/home/me/uv.lock", "uv.lock"],
    [".hidden.cdx.json", "hidden.cdx.json"],
    ["sbom é.cdx.json", "sbom--.cdx.json"],
  ])("%s -> %s", (name, expected) => {
    expect(uploadName(name)).toBe(expected);
  });

  it("keeps the end of a long name, where the parser looks", () => {
    const name = uploadName(`${"x".repeat(150)}-requirements.txt`)!;
    expect(name).toHaveLength(100);
    expect(name.endsWith("-requirements.txt")).toBe(true);
  });

  it.each(["", "...", "日本語", "--"])("refuses %j", (name) => {
    expect(uploadName(name)).toBeNull();
  });
});

describe("fileProblem", () => {
  it("passes an ordinary file", () => {
    expect(fileProblem({ name: "uv.lock", size: 2_000 })).toBeNull();
  });

  it.each([
    [{ name: "a.txt", size: 0 }, "empty"],
    [{ name: "a.txt", size: MAX_UPLOAD_BYTES + 1 }, "over 1 MB"],
    [{ name: "日本語", size: 10 }, "name can't be used"],
  ])("refuses %j", (file, message) => {
    expect(fileProblem(file)).toContain(message);
  });

  it("allows exactly the limit", () => {
    expect(fileProblem({ name: "a.txt", size: MAX_UPLOAD_BYTES })).toBeNull();
  });
});

describe("uploadErrorMessage", () => {
  it.each([
    [new ApiError("http", 422, "bad_file"), "couldn't read that file"],
    [new ApiError("http", 413, "payload_too_large"), "over 1 MB"],
    [new ApiError("http", 503, "queue_unavailable"), "can't start right now"],
    [new ApiError("http", 503, "storage_unavailable"), "can't start right now"],
    [new ApiError("http", 429, "scan_limit"), "Try again later"],
    [new ApiError("http", 429, "scan_limit", 61), "Try again in 2 minutes"],
    [new ApiError("http", 429, "scan_limit", 5), "Try again in 1 minute."],
    [new ApiError("network"), "Can't reach"],
    [new ApiError("http", 500), "returned an error"],
    [new Error("boom: secret detail"), "Something went wrong"],
  ])("%o", (error, message) => {
    expect(uploadErrorMessage(error)).toContain(message);
  });

  it("never echoes anything the server sent", () => {
    expect(uploadErrorMessage(new ApiError("http", 422, "bad_file"))).not.toMatch(/line \d/);
  });
});

describe("scanOutcome", () => {
  it("a complete scan", () => {
    expect(scanOutcome(SCAN)).toEqual({ tone: "good", text: "3 findings in 12 packages." });
  });

  it("singulars", () => {
    expect(scanOutcome({ ...SCAN, findings: 1, dependencies: 1 }).text).toBe("1 finding in 1 package.");
  });

  it("a partial scan never reads as clean", () => {
    const outcome = scanOutcome({ ...SCAN, findings: 0, unchecked: 4, epss_failed: 2, kev_available: false });
    expect(outcome.tone).toBe("warning");
    expect(outcome.text).toBe(
      "0 findings in 12 packages, but 4 packages couldn't be checked; 2 without an EPSS score; " +
        "the CISA KEV list couldn't be loaded.",
    );
  });

  it("an out-of-date KEV list is a warning too", () => {
    expect(scanOutcome({ ...SCAN, kev_stale: true }).text).toContain("out of date");
  });

  it("a failed scan shows the worker's message, or a fixed one", () => {
    expect(scanOutcome({ ...SCAN, status: "failed", error: "Repository not found" })).toEqual({
      tone: "bad",
      text: "Repository not found",
    });
    expect(scanOutcome({ ...SCAN, status: "failed", error: null }).text).toBe("The scan failed. Try again.");
  });
});

describe("scanSchema", () => {
  it("accepts the API's scan and drops fields the UI doesn't use", () => {
    const parsed = scanSchema.parse({ ...SCAN, attempts: 1, created_at: "2026-11-14T10:00:00Z" });
    expect(parsed).toEqual(SCAN);
  });

  it.each([
    { status: "exploded" },
    { findings: -1 },
    { error: "x".repeat(201) },
    { filename: "../etc/passwd" },
    { skipped_examples: Array(21).fill({ ref: "a", reason: "b" }) },
  ])("refuses %j", (change) => {
    expect(scanSchema.safeParse({ ...SCAN, ...change }).success).toBe(false);
  });
});

describe("pollDelay", () => {
  it("asks often at first, then less", () => {
    expect(pollDelay(0)).toBe(2_000);
    expect(pollDelay(59_999)).toBe(2_000);
    expect(pollDelay(60_000)).toBe(5_000);
  });
});
