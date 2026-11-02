"use client";

import Link from "next/link";

import { useAuth } from "@/components/auth-provider";
import { Button } from "@/components/ui/button";

export function UserMenu() {
  const { status, session, signOut } = useAuth();
  if (status === "signed-in" && session) {
    return (
      <div className="ml-auto flex min-w-0 items-center gap-2 text-sm">
        <span className="text-muted-foreground hidden max-w-32 truncate sm:inline" title={session.username}>
          {session.username}
        </span>
        <Button size="sm" variant="ghost" onClick={signOut} title={`Signed in as ${session.username}`}>
          Sign out
        </Button>
      </div>
    );
  }
  if (status === "signed-out") {
    return (
      <Link href="/sign-in" className="ml-auto text-sm underline-offset-4 hover:underline">
        Sign in
      </Link>
    );
  }
  return null;
}
