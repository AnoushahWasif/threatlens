import { z } from "zod";

// The signed-in session, kept in sessionStorage: it survives a reload but not closing the
// tab, and isn't shared between tabs. No refresh token is ever stored, so a stolen copy is
// useful for at most the access token's lifetime (an hour). See ARCHITECTURE.md decision 26.

const KEY = "threatlens.session";
export const SIGNED_OUT_EVENT = "threatlens:signed-out";
/** Fired on every save or clear, so React can re-read the session. */
const CHANGED_EVENT = "threatlens:session";
/** Treat a token as expired a minute early, so a request doesn't race the expiry. */
const MARGIN_MS = 60_000;

const sessionSchema = z.object({
  accessToken: z.string().min(20).max(8_192),
  username: z.string().min(1).max(128),
  expiresAt: z.number().int().positive(),
});

export type Session = z.infer<typeof sessionSchema>;

// Fallback for browsers where sessionStorage throws (some private modes).
let memory: string | null = null;

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

/** The stored value as-is. No side effects, so React can call it on every render. */
export function sessionSnapshot(): string | null {
  try {
    return storage()?.getItem(KEY) ?? memory;
  } catch {
    return memory;
  }
}

export function subscribeSession(onChange: () => void): () => void {
  window.addEventListener(CHANGED_EVENT, onChange);
  return () => window.removeEventListener(CHANGED_EVENT, onChange);
}

/** Null for missing, corrupt or (nearly) expired. */
export function parseSession(raw: string | null, now: number = Date.now()): Session | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const result = sessionSchema.safeParse(parsed);
  if (!result.success || result.data.expiresAt - MARGIN_MS <= now) return null;
  return result.data;
}

/** Like parseSession, but also throws away a stored value that's no longer usable. */
export function readSession(now: number = Date.now()): Session | null {
  const raw = sessionSnapshot();
  const session = parseSession(raw, now);
  if (raw && !session) clearSession();
  return session;
}

function changed() {
  if (typeof window !== "undefined") window.dispatchEvent(new Event(CHANGED_EVENT));
}

export function saveSession(session: Session): void {
  const raw = JSON.stringify(sessionSchema.parse(session));
  memory = raw;
  try {
    storage()?.setItem(KEY, raw);
  } catch {
    // memory only
  }
  changed();
}

export function clearSession(): void {
  memory = null;
  try {
    storage()?.removeItem(KEY);
  } catch {
    // nothing stored
  }
  changed();
}

/** Called when the API says the token is no longer good. */
export function endSession(): void {
  clearSession();
  if (typeof window !== "undefined") window.dispatchEvent(new Event(SIGNED_OUT_EVENT));
}

/**
 * Reads `exp` and `username` from a token for display and expiry only. This is NOT a check:
 * the API verifies the signature on every request.
 */
export function tokenInfo(token: string): { expiresAt: number; username: string | null } | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const json = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
    const claims = z
      .object({ exp: z.number().int().positive(), username: z.string().max(128).optional() })
      .safeParse(JSON.parse(json));
    if (!claims.success) return null;
    return { expiresAt: claims.data.exp * 1000, username: claims.data.username ?? null };
  } catch {
    return null;
  }
}

/**
 * Where to go after sign-in. Only same-site paths: "//evil.example", "/\\evil.example",
 * "https://…" and "javascript:…" all fall back to "/", so ?next= can't become an open redirect.
 */
export function safeNext(raw: string | null | undefined): string {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) return "/";
  if (/[\u0000-\u001f\\]/.test(raw)) return "/";
  try {
    const url = new URL(raw, "https://threatlens.invalid");
    if (url.origin !== "https://threatlens.invalid") return "/";
    if (url.pathname.startsWith("/sign-in") || url.pathname.startsWith("/auth/")) return "/";
    return url.pathname + url.search;
  } catch {
    return "/";
  }
}
