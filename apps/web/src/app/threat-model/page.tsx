"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { NewThreatModel } from "@/components/new-threat-model";
import { ThreatModelView } from "@/components/threat-model-view";

// Same as /findings: a static export can't pre-render a page per model, so the id is ?id=.
function ThreatModelPageBody() {
  const id = useSearchParams().get("id");
  if (!id) return <NewThreatModel />;
  return <ThreatModelView key={id} modelId={id} />;
}

export default function ThreatModelPage() {
  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Threat model</h1>
        <p className="text-muted-foreground text-sm">
          Describe a system, let AI draft STRIDE threats, then accept, reject or rewrite each one.
        </p>
      </div>
      <Suspense fallback={null}>
        <ThreatModelPageBody />
      </Suspense>
    </section>
  );
}
