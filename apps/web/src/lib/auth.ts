import { z } from "zod";

import { ConfigError } from "@/lib/config";
import { type Session, tokenInfo } from "@/lib/session";

export type AuthConfig =
  | { mode: "local" }
  | { mode: "cognito"; domain: string; clientId: string; redirectUri: string; logoutUri: string };

/**
 * NEXT_PUBLIC_ values are baked into the bundle. None of these is a secret: the app client
 * has no client secret, which is why the code flow uses PKCE.
 */
export function authConfig(
  mode: string | undefined = process.env.NEXT_PUBLIC_AUTH_MODE,
  domain: string | undefined = process.env.NEXT_PUBLIC_COGNITO_DOMAIN,
  clientId: string | undefined = process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID,
  origin: string = typeof window === "undefined" ? "http://localhost:3000" : window.location.origin,
): AuthConfig {
  const value = mode?.trim() || "local";
  if (value === "local") return { mode: "local" };
  if (value !== "cognito") throw new ConfigError("NEXT_PUBLIC_AUTH_MODE must be local or cognito");

  let url: URL;
  try {
    url = new URL(domain?.trim() ?? "");
  } catch {
    throw new ConfigError("NEXT_PUBLIC_COGNITO_DOMAIN is not a valid URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new ConfigError("NEXT_PUBLIC_COGNITO_DOMAIN must be a plain https origin");
  }
  if (!clientId || !/^[A-Za-z0-9]{1,128}$/.test(clientId)) {
    throw new ConfigError("NEXT_PUBLIC_COGNITO_CLIENT_ID is missing or malformed");
  }
  return {
    mode: "cognito",
    domain: url.origin,
    clientId,
    redirectUri: `${origin}/auth/callback`,
    logoutUri: `${origin}/`,
  };
}

// --- Cognito hosted UI: authorization code + PKCE ------------------------------

const PKCE_KEY = "threatlens.pkce";
const PKCE_MAX_AGE_MS = 10 * 60_000;
const TOKEN_TIMEOUT_MS = 10_000;

const AUTH_MESSAGES = {
  denied: "Sign-in was cancelled or refused.",
  expired: "That sign-in link has expired. Start again.",
  state: "That sign-in response didn't match a sign-in started here. Start again.",
  exchange: "Couldn't finish signing in with Cognito. Try again.",
} as const;

export class AuthFlowError extends Error {
  constructor(readonly kind: keyof typeof AUTH_MESSAGES) {
    super(AUTH_MESSAGES[kind]);
  }
}

const pkceSchema = z.object({
  state: z.string().min(32).max(128),
  verifier: z.string().min(43).max(128),
  next: z.string().max(2_048),
  createdAt: z.number(),
});

const tokenResponseSchema = z.object({
  access_token: z.string().min(20).max(8_192),
  expires_in: z.number().int().positive().max(86_400),
  token_type: z.literal("Bearer"),
});

function base64url(bytes: Uint8Array): string {
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const randomString = (bytes = 32) => base64url(crypto.getRandomValues(new Uint8Array(bytes)));

async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

/** Saves a one-time state and PKCE verifier for this tab, and returns the hosted UI URL. */
export async function startCognitoSignIn(
  config: Extract<AuthConfig, { mode: "cognito" }>,
  next: string,
  now: number = Date.now(),
): Promise<string> {
  const state = randomString();
  const verifier = randomString(48);
  sessionStorage.setItem(PKCE_KEY, JSON.stringify({ state, verifier, next, createdAt: now }));
  const url = new URL("/oauth2/authorize", config.domain);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: "openid email",
    state,
    code_challenge: await challengeFor(verifier),
    code_challenge_method: "S256",
  }).toString();
  return url.toString();
}

/** Handles /auth/callback: checks state, swaps the code for tokens, keeps only the access token. */
export async function finishCognitoSignIn(
  config: Extract<AuthConfig, { mode: "cognito" }>,
  params: URLSearchParams,
  { fetchImpl = fetch, now = Date.now() }: { fetchImpl?: typeof fetch; now?: number } = {},
): Promise<{ session: Session; next: string }> {
  // Read once and delete straight away, so a response can't be replayed in this tab.
  const raw = sessionStorage.getItem(PKCE_KEY);
  sessionStorage.removeItem(PKCE_KEY);

  if (params.has("error")) throw new AuthFlowError("denied");
  let saved: z.infer<typeof pkceSchema>;
  try {
    saved = pkceSchema.parse(JSON.parse(raw ?? ""));
  } catch {
    throw new AuthFlowError("expired");
  }
  if (now - saved.createdAt > PKCE_MAX_AGE_MS) throw new AuthFlowError("expired");
  if (params.get("state") !== saved.state) throw new AuthFlowError("state");
  const code = params.get("code");
  if (!code || !/^[A-Za-z0-9._~-]{1,2048}$/.test(code)) throw new AuthFlowError("state");

  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), TOKEN_TIMEOUT_MS);
  let body: unknown;
  try {
    const response = await fetchImpl(new URL("/oauth2/token", config.domain).toString(), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.clientId,
        code,
        redirect_uri: config.redirectUri,
        code_verifier: saved.verifier,
      }).toString(),
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      signal: timeout.signal,
    });
    if (!response.ok) throw new AuthFlowError("exchange");
    body = await response.json();
  } catch {
    throw new AuthFlowError("exchange");
  } finally {
    clearTimeout(timer);
  }

  // The response also has id and refresh tokens. They're dropped here and never stored.
  const tokens = tokenResponseSchema.safeParse(body);
  if (!tokens.success) throw new AuthFlowError("exchange");
  const info = tokenInfo(tokens.data.access_token);
  const expiresAt = Math.min(now + tokens.data.expires_in * 1000, info?.expiresAt ?? Infinity);
  return {
    session: { accessToken: tokens.data.access_token, username: info?.username ?? "you", expiresAt },
    next: saved.next,
  };
}

export function cognitoLogoutUrl(config: Extract<AuthConfig, { mode: "cognito" }>): string {
  const url = new URL("/logout", config.domain);
  url.search = new URLSearchParams({ client_id: config.clientId, logout_uri: config.logoutUri }).toString();
  return url.toString();
}
