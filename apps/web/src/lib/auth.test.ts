import { beforeEach, describe, expect, it, vi } from "vitest";

import { AuthFlowError, authConfig, cognitoLogoutUrl, finishCognitoSignIn, startCognitoSignIn } from "@/lib/auth";
import { ConfigError } from "@/lib/config";

const DOMAIN = "https://threatlens.auth.eu-west-2.amazoncognito.com";
const ORIGIN = "https://threatlens.example.com";
const config = authConfig("cognito", DOMAIN, "abc123client", ORIGIN) as Extract<
  ReturnType<typeof authConfig>,
  { mode: "cognito" }
>;

function accessToken(payload: object) {
  const b64 = btoa(JSON.stringify(payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `eyJhbGciOiJSUzI1NiJ9.${b64}.signature`;
}

beforeEach(() => {
  sessionStorage.clear();
});

describe("authConfig", () => {
  it("defaults to local", () => {
    expect(authConfig(undefined, undefined, undefined, ORIGIN)).toEqual({ mode: "local" });
  });

  it("builds the Cognito settings from a plain https domain", () => {
    expect(config).toEqual({
      mode: "cognito",
      domain: DOMAIN,
      clientId: "abc123client",
      redirectUri: `${ORIGIN}/auth/callback`,
      logoutUri: `${ORIGIN}/`,
    });
  });

  it.each([
    ["sso", DOMAIN, "abc"],
    ["cognito", "http://threatlens.auth.eu-west-2.amazoncognito.com", "abc"],
    ["cognito", `${DOMAIN}/oauth2`, "abc"],
    ["cognito", `${DOMAIN}?x=1`, "abc"],
    ["cognito", "https://user:pw@evil.example", "abc"],
    ["cognito", "not a url", "abc"],
    ["cognito", DOMAIN, undefined],
    ["cognito", DOMAIN, "abc&redirect_uri=https://evil.example"],
  ])("rejects mode=%j domain=%j client=%j", (mode, domain, client) => {
    expect(() => authConfig(mode, domain, client, ORIGIN)).toThrow(ConfigError);
  });
});

describe("Cognito code flow with PKCE", () => {
  it("sends the browser to the hosted UI with S256 PKCE and a random state", async () => {
    const url = new URL(await startCognitoSignIn(config, "/findings"));
    expect(url.origin + url.pathname).toBe(`${DOMAIN}/oauth2/authorize`);
    const p = url.searchParams;
    expect(p.get("response_type")).toBe("code");
    expect(p.get("client_id")).toBe("abc123client");
    expect(p.get("redirect_uri")).toBe(`${ORIGIN}/auth/callback`);
    expect(p.get("code_challenge_method")).toBe("S256");
    expect(p.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const saved = JSON.parse(sessionStorage.getItem("threatlens.pkce")!);
    expect(saved.state).toBe(p.get("state"));
    // The challenge is SHA-256 of the saved verifier, and the verifier itself is never sent.
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(saved.verifier));
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(p.get("code_challenge")).toBe(expected);
    expect(url.toString()).not.toContain(saved.verifier);
  });

  it("uses a new state every time", async () => {
    const a = new URL(await startCognitoSignIn(config, "/")).searchParams.get("state");
    const b = new URL(await startCognitoSignIn(config, "/")).searchParams.get("state");
    expect(a).not.toBe(b);
  });

  async function callback(overrides: Record<string, string> = {}) {
    await startCognitoSignIn(config, "/threat-model");
    const { state } = JSON.parse(sessionStorage.getItem("threatlens.pkce")!);
    return new URLSearchParams({ code: "6f1c2a3b-code", state, ...overrides });
  }

  const tokenReply = (body: object, status = 200) =>
    vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(body), { status }));

  it("swaps the code for tokens and keeps only the access token", async () => {
    const params = await callback();
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const fetchImpl = tokenReply({
      access_token: accessToken({ exp, username: "anoushah" }),
      id_token: "id-token-not-kept",
      refresh_token: "refresh-token-not-kept",
      expires_in: 3600,
      token_type: "Bearer",
    });
    const { session, next } = await finishCognitoSignIn(config, params, { fetchImpl });
    expect(next).toBe("/threat-model");
    expect(session.username).toBe("anoushah");
    expect(JSON.stringify(session)).not.toContain("refresh-token-not-kept");
    expect(JSON.stringify(session)).not.toContain("id-token-not-kept");

    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(`${DOMAIN}/oauth2/token`);
    expect(init).toMatchObject({ method: "POST", credentials: "omit", redirect: "error" });
    const form = new URLSearchParams(String(init?.body));
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{64}$/);
    expect(form.has("client_secret")).toBe(false);
    // Single use: the saved state is gone.
    expect(sessionStorage.getItem("threatlens.pkce")).toBeNull();
  });

  it.each([
    ["a state that doesn't match", { state: "x".repeat(43) }, "state"],
    ["an error from Cognito", { error: "access_denied" }, "denied"],
    ["a code with odd characters", { code: "abc def<script>" }, "state"],
  ] as const)("refuses %s, without calling the token endpoint", async (_name, overrides, kind) => {
    const params = await callback(overrides);
    const fetchImpl = vi.fn<typeof fetch>();
    const error = await finishCognitoSignIn(config, params, { fetchImpl }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthFlowError);
    expect((error as AuthFlowError).kind).toBe(kind);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("refuses a callback with no sign-in started in this tab, and a replay", async () => {
    const params = await callback();
    const ok = tokenReply({ access_token: accessToken({ exp: 9_999_999_999 }), expires_in: 3600, token_type: "Bearer" });
    await finishCognitoSignIn(config, params, { fetchImpl: ok });
    const replay = await finishCognitoSignIn(config, params, { fetchImpl: ok }).catch((e: unknown) => e);
    expect((replay as AuthFlowError).kind).toBe("expired");
  });

  it("refuses a sign-in started more than 10 minutes ago", async () => {
    const params = await callback();
    const later = Date.now() + 11 * 60_000;
    const error = await finishCognitoSignIn(config, params, { fetchImpl: vi.fn(), now: later }).catch((e) => e);
    expect((error as AuthFlowError).kind).toBe("expired");
  });

  it.each([
    ["a failed exchange", { error: "invalid_grant" }, 400],
    ["a reply without a bearer token", { access_token: "x".repeat(40), expires_in: 3600, token_type: "mac" }, 200],
    ["a reply with a silly lifetime", { access_token: "x".repeat(40), expires_in: 10_000_000, token_type: "Bearer" }, 200],
  ])("turns %s into one fixed message", async (_name, body, status) => {
    const params = await callback();
    const error = await finishCognitoSignIn(config, params, { fetchImpl: tokenReply(body, status) }).catch((e) => e);
    expect((error as AuthFlowError).kind).toBe("exchange");
    expect((error as Error).message).toBe("Couldn't finish signing in with Cognito. Try again.");
  });

  it("never trusts expires_in past the token's own exp", async () => {
    const params = await callback();
    const exp = Math.floor(Date.now() / 1000) + 600;
    const fetchImpl = tokenReply({ access_token: accessToken({ exp }), expires_in: 3600, token_type: "Bearer" });
    const { session } = await finishCognitoSignIn(config, params, { fetchImpl });
    expect(session.expiresAt).toBe(exp * 1000);
  });

  it("logs out of the hosted UI too", () => {
    const url = new URL(cognitoLogoutUrl(config));
    expect(url.origin + url.pathname).toBe(`${DOMAIN}/logout`);
    expect(url.searchParams.get("logout_uri")).toBe(`${ORIGIN}/`);
  });
});
