import { describe, expect, it } from "vitest";

import { apiBaseUrl, ConfigError } from "@/lib/config";

describe("apiBaseUrl", () => {
  it.each([undefined, "", "   "])("is null when unset (%j)", (raw) => {
    expect(apiBaseUrl(raw)).toBeNull();
  });

  it.each([
    ["https://api.threatlens.dev", "https://api.threatlens.dev"],
    ["https://api.threatlens.dev/", "https://api.threatlens.dev"],
    ["https://abc.execute-api.eu-west-1.amazonaws.com/prod//", "https://abc.execute-api.eu-west-1.amazonaws.com/prod"],
    ["http://localhost:8000", "http://localhost:8000"],
    ["http://127.0.0.1:8000/", "http://127.0.0.1:8000"],
  ])("accepts %s", (raw, expected) => {
    expect(apiBaseUrl(raw)).toBe(expected);
  });

  it.each([
    "not a url",
    "http://api.threatlens.dev",
    "ftp://api.threatlens.dev",
    "javascript:alert(1)",
    "https://user:pass@api.threatlens.dev",
    "https://api.threatlens.dev/?debug=1",
    "https://api.threatlens.dev/#x",
  ])("rejects %s", (raw) => {
    expect(() => apiBaseUrl(raw)).toThrow(ConfigError);
  });
});
