"use client";

import Link from "next/link";
import { useState } from "react";

import { ThreatCard } from "@/components/threat-card";
import { ThreatForm } from "@/components/threat-form";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useThreatModel } from "@/hooks/use-threat-model";
import { errorMessage } from "@/lib/threat-errors";
import {
  countByStatus,
  EMPTY_THREAT,
  exportFilename,
  groupByCategory,
  LIMITS,
  STRIDE_LABELS,
  type ThreatModel,
  type ThreatStatus,
  toMarkdown,
} from "@/lib/threats";

type Filter = "all" | ThreatStatus;
const FILTERS: { value: Filter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "draft", label: "To review" },
  { value: "accepted", label: "Accepted" },
  { value: "rejected", label: "Rejected" },
];

function download(model: ThreatModel) {
  const blob = new Blob([toMarkdown(model)], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = exportFilename(model.name);
  a.click();
  URL.revokeObjectURL(url);
}

export function ThreatModelView({ modelId }: { modelId: string }) {
  const { state, retry, actions } = useThreatModel(modelId);
  const [filter, setFilter] = useState<Filter>("all");
  const [adding, setAdding] = useState(false);
  const [drafting, setDrafting] = useState(false);
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  if (state.status === "loading") {
    return (
      <div className="space-y-3" aria-busy="true" aria-label="Loading threat model">
        <Skeleton className="h-8 w-1/2" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div role="alert" className="rounded-lg border border-destructive/40 p-6">
        <p className="font-medium">{state.message}</p>
        {state.notFound ? (
          <Link href="/threat-model" className="mt-3 inline-block text-sm underline underline-offset-4">
            Start a new threat model
          </Link>
        ) : (
          <Button variant="outline" size="sm" className="mt-3" onClick={retry}>
            Try again
          </Button>
        )}
      </div>
    );
  }

  const { model, source } = state;
  const counts = countByStatus(model.threats);
  const shown = filter === "all" ? model.threats : model.threats.filter((t) => t.status === filter);
  const full = model.threats.length >= LIMITS.threats;

  async function draft() {
    setDrafting(true);
    setNotice(null);
    try {
      const updated = await actions.draft();
      const added = updated.threats.filter((t) => t.source === "llm" && t.status === "draft").length;
      setNotice({
        kind: "ok",
        text: `${added} AI-drafted threat${added === 1 ? "" : "s"} to review. Anything you had reviewed or edited was kept.`,
      });
    } catch (error) {
      setNotice({ kind: "error", text: errorMessage(error) });
    } finally {
      setDrafting(false);
    }
  }

  return (
    <div className="space-y-6">
      {source === "sample" && (
        <p className="text-muted-foreground rounded-md bg-muted px-3 py-2 text-sm">
          Sample data: no API is configured (set <code>NEXT_PUBLIC_API_URL</code>). Drafts here are
          fixed examples, not from an AI, and changes are lost when you reload.
        </p>
      )}

      <div className="space-y-2">
        <h2 className="text-xl font-semibold tracking-tight break-words">{model.name}</h2>
        <p className="text-muted-foreground text-sm">
          {model.drafted_at
            ? `Last drafted ${new Date(model.drafted_at).toLocaleString("en-GB")} with ${model.drafted_with ?? "an unknown model"}.`
            : "Not drafted yet."}{" "}
          {counts.draft} to review · {counts.accepted} accepted · {counts.rejected} rejected
        </p>
        <details className="text-sm">
          <summary className="text-muted-foreground cursor-pointer">Architecture description</summary>
          <p className="mt-2 rounded-md border p-3 break-words whitespace-pre-line">{model.architecture}</p>
        </details>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={draft} disabled={drafting}>
          {drafting ? "Drafting…" : model.drafted_at ? "Draft again with AI" : "Draft with AI"}
        </Button>
        <Button variant="outline" onClick={() => setAdding(true)} disabled={adding || full}>
          Add a threat
        </Button>
        <Button
          variant="outline"
          onClick={() => download(model)}
          disabled={counts.accepted === 0}
          title={counts.accepted === 0 ? "Accept at least one threat to export" : undefined}
        >
          Export Markdown
        </Button>
      </div>
      <p className="text-muted-foreground -mt-4 text-xs">
        AI drafts are suggestions: nothing counts until you accept it. Drafting again replaces only
        drafts nobody has reviewed or edited. The export includes accepted threats only.
      </p>

      {notice && (
        <p
          role={notice.kind === "error" ? "alert" : "status"}
          className={notice.kind === "error" ? "text-destructive text-sm" : "text-sm"}
        >
          {notice.text}
        </p>
      )}

      {adding && (
        <div className="rounded-lg border p-4">
          <h3 className="mb-3 font-medium">New threat</h3>
          <ThreatForm
            initial={EMPTY_THREAT}
            submitLabel="Add threat"
            onCancel={() => setAdding(false)}
            onSubmit={async (input) => {
              await actions.add(input);
              setAdding(false);
            }}
          />
        </div>
      )}

      <div role="group" aria-label="Show threats" className="flex flex-wrap gap-1">
        {FILTERS.map((f) => (
          <Button
            key={f.value}
            size="sm"
            variant={filter === f.value ? "secondary" : "ghost"}
            aria-pressed={filter === f.value}
            onClick={() => setFilter(f.value)}
          >
            {f.label}
          </Button>
        ))}
      </div>

      {model.threats.length === 0 ? (
        <p className="text-muted-foreground rounded-lg border border-dashed p-6 text-center text-sm">
          No threats yet. Draft them with AI, or add your own.
        </p>
      ) : shown.length === 0 ? (
        <p className="text-muted-foreground text-sm">Nothing in this view.</p>
      ) : (
        groupByCategory(shown).map(([category, threats]) => (
          <section key={category} aria-labelledby={`stride-${category}`} className="space-y-3">
            <h3 id={`stride-${category}`} className="font-medium">
              {STRIDE_LABELS[category]} <span className="text-muted-foreground text-sm">({threats.length})</span>
            </h3>
            <ul className="space-y-3">
              {threats.map((t) => (
                <ThreatCard
                  key={t.id}
                  threat={t}
                  onUpdate={(patch) => actions.update(t.id, patch)}
                  onDelete={() => actions.remove(t.id)}
                />
              ))}
            </ul>
          </section>
        ))
      )}
    </div>
  );
}
