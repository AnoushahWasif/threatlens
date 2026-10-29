"use client";

import Link from "next/link";

import { FindingsTable } from "@/components/findings-table";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useFindings } from "@/hooks/use-findings";

export function FindingsView({ projectId }: { projectId: string }) {
  const { state, retry } = useFindings(projectId);

  if (state.status === "loading") {
    return (
      <div className="space-y-3" aria-busy="true" aria-label="Loading findings">
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-9 w-full" />
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div role="alert" className="rounded-lg border border-destructive/40 p-6">
        <p className="font-medium">{state.message}</p>
        {state.notFound ? (
          <Link href="/" className="mt-3 inline-block text-sm underline underline-offset-4">
            Back to projects
          </Link>
        ) : (
          <Button variant="outline" size="sm" className="mt-3" onClick={retry}>
            Try again
          </Button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {state.source === "sample" && (
        <p className="text-muted-foreground rounded-md bg-muted px-3 py-2 text-sm">
          Sample data: no API is configured (set <code>NEXT_PUBLIC_API_URL</code>).
        </p>
      )}
      <FindingsTable findings={state.findings} />
    </div>
  );
}
