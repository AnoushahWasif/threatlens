import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api-error";
import { errorMessage } from "@/lib/threat-errors";

describe("errorMessage for storage errors", () => {
  it.each([
    ["edit_conflict", 409, /changed somewhere else/],
    ["too_large", 409, /too big to save/],
    ["storage_busy", 503, /busy/],
    ["storage_unavailable", 503, /can't reach its storage/],
    ["write_limit", 429, /a lot of changes this hour/],
  ] as const)("gives fixed text for %s", (code, status, text) => {
    expect(errorMessage(new ApiError("http", status, code))).toMatch(text);
  });

  it("falls back to the generic message for a code it doesn't know", () => {
    expect(errorMessage(new ApiError("http", 500))).toBe("The ThreatLens API returned an error.");
  });
});
