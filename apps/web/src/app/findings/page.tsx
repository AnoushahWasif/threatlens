"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { FindingsView } from "@/components/findings-view";

// A static export can't pre-render a page per project, so the id travels as ?project=.
function Findings() {
  const projectId = useSearchParams().get("project") ?? "";
  return <FindingsView key={projectId} projectId={projectId} />;
}

export default function FindingsPage() {
  return (
    <section className="space-y-6">
      <div>
        <Link href="/" className="text-muted-foreground text-sm underline-offset-4 hover:underline">
          ← Projects
        </Link>
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="text-muted-foreground text-sm">
          Ranked by risk: 100 × likelihood (KEV, else EPSS) × severity weight. Unscored findings
          come last because missing data isn&apos;t the same as low risk.
        </p>
      </div>
      <Suspense fallback={null}>
        <Findings />
      </Suspense>
    </section>
  );
}
