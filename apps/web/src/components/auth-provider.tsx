"use client";

import { useRouter } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, useSyncExternalStore } from "react";

import { type AuthConfig, authConfig, cognitoLogoutUrl } from "@/lib/auth";
import { apiBaseUrl } from "@/lib/config";
import {
  clearSession,
  parseSession,
  saveSession,
  type Session,
  sessionSnapshot,
  subscribeSession,
} from "@/lib/session";

type Auth = {
  /** "loading" until the browser's stored session has been read (it can't be read while prerendering). */
  status: "loading" | "signed-in" | "signed-out" | "not-needed";
  session: Session | null;
  config: AuthConfig | null;
  configError: boolean;
  signIn: (session: Session) => void;
  signOut: () => void;
};

const AuthContext = createContext<Auth | null>(null);

function settings(): { config: AuthConfig | null; needed: boolean; error: boolean } {
  try {
    // With no API configured the app runs on sample data, and there's nothing to protect.
    const needed = apiBaseUrl() !== null;
    return { config: authConfig(), needed, error: false };
  } catch {
    return { config: null, needed: true, error: true };
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [{ config, needed, error }] = useState(settings);
  // undefined while prerendering: the stored session only exists in the browser.
  const raw = useSyncExternalStore(subscribeSession, sessionSnapshot, () => undefined);
  const loaded = raw !== undefined;
  const session = useMemo(() => (raw ? parseSession(raw) : null), [raw]);

  // Drop the session the moment it expires, not on the next failed request.
  useEffect(() => {
    if (raw && !session) {
      clearSession();
      return;
    }
    if (!session) return;
    const timer = setTimeout(clearSession, Math.max(0, session.expiresAt - Date.now() - 59_000));
    return () => clearTimeout(timer);
  }, [raw, session]);

  const signIn = useCallback((next: Session) => saveSession(next), []);

  const signOut = useCallback(() => {
    clearSession();
    // Also end the hosted-UI session, or "Sign in" would log straight back in.
    if (config?.mode === "cognito") window.location.assign(cognitoLogoutUrl(config));
  }, [config]);

  const value = useMemo<Auth>(
    () => ({
      status: !needed ? "not-needed" : !loaded ? "loading" : session ? "signed-in" : "signed-out",
      session,
      config,
      configError: error,
      signIn,
      signOut,
    }),
    [needed, loaded, session, config, error, signIn, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): Auth {
  const auth = useContext(AuthContext);
  if (!auth) throw new Error("useAuth must be used inside <AuthProvider>");
  return auth;
}

/** Shows its children only to a signed-in user; anyone else is sent to sign in and back. */
export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { status, configError } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (status !== "signed-out" || configError) return;
    const here = window.location.pathname + window.location.search;
    router.replace(`/sign-in?next=${encodeURIComponent(here)}`);
  }, [status, configError, router]);

  if (configError) {
    return (
      <p role="alert" className="rounded-lg border border-destructive/40 p-6 font-medium">
        Sign-in isn&apos;t set up correctly on this site (check the NEXT_PUBLIC_AUTH and COGNITO settings).
      </p>
    );
  }
  if (status === "loading" || status === "signed-out") {
    return <p className="text-muted-foreground text-sm" aria-busy="true">Checking sign-in…</p>;
  }
  return <>{children}</>;
}
