"use client";

import { useState } from "react";

import { ThreatForm } from "@/components/threat-form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { errorMessage } from "@/lib/threat-errors";
import type { Threat, ThreatInput, ThreatPatch, ThreatStatus } from "@/lib/threats";

const STATUS_TEXT: Record<ThreatStatus, string> = {
  draft: "To review",
  accepted: "Accepted",
  rejected: "Rejected",
};

type Props = {
  threat: Threat;
  onUpdate: (patch: ThreatPatch) => Promise<void>;
  onDelete: () => Promise<void>;
};

export function ThreatCard({ threat, onUpdate, onDelete }: Props) {
  const [mode, setMode] = useState<"view" | "edit" | "confirm-delete">("view");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setFailure(null);
    try {
      await action();
    } catch (error) {
      setFailure(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  const setStatus = (status: ThreatStatus) => run(() => onUpdate({ status }));

  if (mode === "edit") {
    const initial: ThreatInput = {
      category: threat.category,
      title: threat.title,
      description: threat.description,
      mitigation: threat.mitigation,
      component: threat.component,
    };
    return (
      <li className="rounded-lg border p-4">
        <ThreatForm
          initial={initial}
          submitLabel="Save changes"
          onCancel={() => setMode("view")}
          onSubmit={async (input) => {
            // Send only what changed, so an unchanged save doesn't mark the threat as edited.
            const patch = Object.fromEntries(
              Object.entries(input).filter(([k, v]) => initial[k as keyof ThreatInput] !== v),
            );
            if (Object.keys(patch).length > 0) await onUpdate(patch);
            setMode("view");
          }}
        />
      </li>
    );
  }

  return (
    <li
      className="rounded-lg border p-4"
      data-status={threat.status}
      aria-label={threat.title}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <h4 className="font-medium break-words">{threat.title}</h4>
          <div className="flex flex-wrap gap-1.5">
            <Badge variant={threat.status === "accepted" ? "default" : "outline"}>
              {STATUS_TEXT[threat.status]}
            </Badge>
            <Badge variant="secondary">
              {threat.source === "llm" ? (threat.edited ? "AI draft, edited" : "AI draft") : "Written by hand"}
            </Badge>
            {threat.component && <Badge variant="outline">{threat.component}</Badge>}
          </div>
        </div>
      </div>

      <p className="mt-3 text-sm break-words whitespace-pre-line">{threat.description}</p>
      <p className="text-muted-foreground mt-2 text-sm break-words whitespace-pre-line">
        <span className="text-foreground font-medium">Mitigation: </span>
        {threat.mitigation || "none yet"}
      </p>

      {failure && (
        <p role="alert" className="text-destructive mt-2 text-sm">
          {failure}
        </p>
      )}

      <div className="mt-3 flex flex-wrap gap-2" aria-busy={busy || undefined}>
        {mode === "confirm-delete" ? (
          <>
            <Button size="sm" variant="destructive" disabled={busy} onClick={() => run(onDelete)}>
              Confirm delete
            </Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => setMode("view")}>
              Keep it
            </Button>
          </>
        ) : (
          <>
            {threat.status !== "accepted" && (
              <Button size="sm" disabled={busy} onClick={() => setStatus("accepted")}>
                Accept
              </Button>
            )}
            {threat.status !== "rejected" && (
              <Button size="sm" variant="outline" disabled={busy} onClick={() => setStatus("rejected")}>
                Reject
              </Button>
            )}
            {threat.status !== "draft" && (
              <Button size="sm" variant="ghost" disabled={busy} onClick={() => setStatus("draft")}>
                Back to review
              </Button>
            )}
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => setMode("edit")}>
              Edit
            </Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => setMode("confirm-delete")}>
              Delete
            </Button>
          </>
        )}
      </div>
    </li>
  );
}
