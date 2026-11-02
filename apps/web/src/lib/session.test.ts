import { beforeEach, describe, expect, it } from "vitest";

import { clearSession, readSession, safeNext, saveSession, tokenInfo } from "@/lib/session";

const HOUR = 3_600_000;
const session = (expiresAt: number) => ({ accessToken: "t".repeat(40), username: "alice", expiresAt });

function jwtWith(payload: object): string {
  const b64 = btoa(JSON.stringify(payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `eyJhbGciOiJSUzI1NiJ9.${b64}.sig`;
}

beforeEach(() => {
  clearSession();
});

describe("session storage", () => {
  it("keeps a session for this tab only (sessionStorage, not localStorage)", () => {
    saveSession(session(Date.now() + HOUR));
    expect(readSession()?.username).toBe("alice");
    expect(window.sessionStorage.getItem("threatlens.session")).not.toBeNull();
    expect(window.localStorage.length).toBe(0);
  });

  it("drops a session a minute before it expires", () => {
    const now = Date.now();
    saveSession(session(now + 59_000));
    expect(readSession(now)).toBeNull();
    expect(window.sessionStorage.getItem("threatlens.session")).toBeNull();
  });

  it.each([["not json"], [JSON.stringify({ accessToken: "short", username: "a", expiresAt: 1 })], ["null"]])(
    "throws away a corrupt stored value: %s",
    (raw) => {
      window.sessionStorage.setItem("threatlens.session", raw);
      expect(readSession()).toBeNull();
      expect(window.sessionStorage.getItem("threatlens.session")).toBeNull();
    },
  );

  it("clears on sign out", () => {
    saveSession(session(Date.now() + HOUR));
    clearSession();
    expect(readSession()).toBeNull();
  });
});

describe("tokenInfo (display only, never a check)", () => {
  it("reads exp and username", () => {
    expect(tokenInfo(jwtWith({ exp: 2_000_000_000, username: "anoushah" }))).toEqual({
      expiresAt: 2_000_000_000_000,
      username: "anoushah",
    });
  });

  it.each(["", "abc", "a.b.c", jwtWith({ exp: "soon" }), jwtWith({ username: "x" })])(
    "returns null for %j",
    (token) => {
      expect(tokenInfo(token)).toBeNull();
    },
  );
});

describe("safeNext", () => {
  it.each([
    ["/findings?project=abc", "/findings?project=abc"],
    ["/threat-model?id=5d2c8b1e-7a4f-4c3d-9e6b-1f0a2d3c4b5e", "/threat-model?id=5d2c8b1e-7a4f-4c3d-9e6b-1f0a2d3c4b5e"],
    ["/", "/"],
    // Encoded characters stay encoded: a same-site path that 404s, not a header split.
    ["/%0d%0aevil", "/%0d%0aevil"],
  ])("keeps the same-site path %j", (input, expected) => {
    expect(safeNext(input)).toBe(expected);
  });

  it.each([
    null,
    "",
    "https://evil.example/",
    "//evil.example/path",
    "/\\evil.example",
    "\\\\evil.example",
    "javascript:alert(1)",
    "/\tevil",
    "evil.example",
    "/sign-in?next=//evil.example",
    "/auth/callback?code=x",
  ])("falls back to / for %j", (input) => {
    expect(safeNext(input)).toBe("/");
  });
});
