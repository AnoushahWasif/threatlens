"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";

import { useAuth } from "@/components/auth-provider";
import { Button } from "@/components/ui/button";
import { ApiError, requestLocalToken } from "@/lib/api";
import { AuthFlowError, finishCognitoSignIn, startCognitoSignIn } from "@/lib/auth";
import { safeNext, tokenInfo } from "@/lib/session";

const USERNAME = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const FIELD =
  "border-input bg-background w-full max-w-xs rounded-md border px-2.5 py-1.5 text-sm outline-none focus-visible:ring-3 focus-visible:ring-ring/50 aria-invalid:border-destructive";

export function SignIn({ next }: { next: string | null }) {
  const id = useId();
  const router = useRouter();
  const { status, session, config, configError, signIn } = useAuth();
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const target = safeNext(next);

  if (configError || !config) {
    return (
      <p role="alert" className="font-medium">
        Sign-in isn&apos;t set up correctly on this site.
      </p>
    );
  }
  if (status === "not-needed") {
    return (
      <p className="text-sm">
        No API is configured, so the app runs on sample data and there&apos;s nothing to sign in to.{" "}
        <Link href="/" className="underline underline-offset-4">
          Go to projects
        </Link>
      </p>
    );
  }
  if (status === "signed-in" && session) {
    return (
      <p className="text-sm">
        Signed in as <strong>{session.username}</strong>.{" "}
        <Link href={target} className="underline underline-offset-4">
          Continue
        </Link>
      </p>
    );
  }

  if (config.mode === "cognito") {
    return (
      <div className="space-y-3">
        <Button
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            window.location.assign(await startCognitoSignIn(config, target));
          }}
        >
          {busy ? "Opening sign-in…" : "Sign in"}
        </Button>
        <p className="text-muted-foreground text-xs">You&apos;ll be taken to the ThreatLens sign-in page (Amazon Cognito) and back.</p>
      </div>
    );
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!USERNAME.test(username)) {
      setFailure("Use 1–32 lower-case letters, digits, dots, dashes or underscores.");
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      const { access_token, expires_in } = await requestLocalToken(username);
      const info = tokenInfo(access_token);
      signIn({
        accessToken: access_token,
        username: info?.username ?? username,
        expiresAt: Math.min(Date.now() + expires_in * 1000, info?.expiresAt ?? Infinity),
      });
      router.replace(target);
    } catch (error) {
      setFailure(error instanceof ApiError ? error.message : "Couldn't sign in. Try again.");
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} noValidate className="space-y-3">
      <p className="text-muted-foreground rounded-md bg-muted px-3 py-2 text-sm">
        Local development sign-in: any name works and no password is checked. A deployed site uses
        Cognito instead, and the API refuses this mode in production.
      </p>
      <div className="space-y-1">
        <label htmlFor={`${id}-user`} className="block text-sm font-medium">
          Username
        </label>
        <input
          id={`${id}-user`}
          value={username}
          autoComplete="username"
          onChange={(e) => {
            setUsername(e.target.value);
            setFailure(null);
          }}
          aria-invalid={failure !== null ? true : undefined}
          aria-describedby={failure ? `${id}-error` : undefined}
          className={FIELD}
        />
        {failure && (
          <p id={`${id}-error`} role="alert" className="text-destructive text-xs">
            {failure}
          </p>
        )}
      </div>
      <Button type="submit" disabled={busy}>
        {busy ? "Signing in…" : "Sign in"}
      </Button>
    </form>
  );
}

/** /auth/callback: Cognito sends the browser back here with ?code=…&state=… */
export function AuthCallback() {
  const router = useRouter();
  const { config, signIn } = useAuth();
  const [failure, setFailure] = useState<string | null>(null);
  // The saved state is single-use, so the exchange must run once even if effects run twice.
  const started = useRef(false);

  useEffect(() => {
    if (started.current || config?.mode !== "cognito") return;
    started.current = true;
    const params = new URLSearchParams(window.location.search);
    // Remove the code from the address bar and history straight away.
    window.history.replaceState(null, "", "/auth/callback");
    finishCognitoSignIn(config, params).then(
      ({ session, next }) => {
        signIn(session);
        router.replace(safeNext(next));
      },
      (error: unknown) =>
        setFailure(error instanceof AuthFlowError ? error.message : "Couldn't finish signing in."),
    );
  }, [config, signIn, router]);

  if (config?.mode !== "cognito") {
    return <p className="text-sm">This page is only used with Cognito sign-in.</p>;
  }
  if (failure) {
    return (
      <div role="alert" className="space-y-2">
        <p className="font-medium">{failure}</p>
        <Link href="/sign-in" className="text-sm underline underline-offset-4">
          Back to sign in
        </Link>
      </div>
    );
  }
  return <p className="text-muted-foreground text-sm" aria-busy="true">Finishing sign-in…</p>;
}
