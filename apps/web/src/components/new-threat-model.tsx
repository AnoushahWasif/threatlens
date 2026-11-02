"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useId, useState } from "react";

import { Button } from "@/components/ui/button";
import { useBackend } from "@/hooks/use-threat-model";
import { SAMPLE_MODEL_ID } from "@/lib/sample-threat-models";
import { errorMessage } from "@/lib/threat-errors";
import { LIMITS, modelErrors, type ModelInput } from "@/lib/threats";

const FIELD =
  "border-input bg-background w-full rounded-md border px-2.5 py-1.5 text-sm outline-none focus-visible:ring-3 focus-visible:ring-ring/50 aria-invalid:border-destructive";

export function NewThreatModel() {
  const id = useId();
  const router = useRouter();
  const backend = useBackend();
  const [values, setValues] = useState<ModelInput>({ name: "", architecture: "" });
  const [shown, setShown] = useState(false);
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const errors = shown ? modelErrors(values) : {};
  const length = values.architecture.trim().length;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setShown(true);
    if (!backend) return setFailure(errorMessage(null));
    if (Object.keys(modelErrors(values)).length > 0) return;
    setSaving(true);
    setFailure(null);
    try {
      const model = await backend.create({
        name: values.name.trim(),
        architecture: values.architecture.trim(),
      });
      // model.id passed the schema's UUID check, so this is never an arbitrary URL.
      router.push(`/threat-model?id=${model.id}`);
    } catch (error) {
      setFailure(errorMessage(error));
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      {backend?.source === "sample" && (
        <p className="text-muted-foreground rounded-md bg-muted px-3 py-2 text-sm">
          Sample data: no API is configured. A model you create here lives only until you reload.{" "}
          <Link href={`/threat-model?id=${SAMPLE_MODEL_ID}`} className="text-foreground underline underline-offset-4">
            Open the sample model
          </Link>
        </p>
      )}
      <form onSubmit={submit} noValidate className="max-w-2xl space-y-4">
        <div className="space-y-1">
          <label htmlFor={`${id}-name`} className="text-sm font-medium">
            Name
          </label>
          <input
            id={`${id}-name`}
            value={values.name}
            maxLength={LIMITS.name * 2}
            onChange={(e) => setValues((v) => ({ ...v, name: e.target.value }))}
            aria-invalid={errors.name ? true : undefined}
            aria-describedby={errors.name ? `${id}-name-error` : undefined}
            className={FIELD}
          />
          {errors.name && (
            <p id={`${id}-name-error`} className="text-destructive text-xs">
              {errors.name}
            </p>
          )}
        </div>
        <div className="space-y-1">
          <label htmlFor={`${id}-arch`} className="text-sm font-medium">
            Architecture description
          </label>
          <p id={`${id}-arch-hint`} className="text-muted-foreground text-xs">
            What the parts are, what talks to what, where data is stored and who uses it. This text
            is sent to the AI when you draft, so leave out secrets.
          </p>
          <textarea
            id={`${id}-arch`}
            rows={8}
            value={values.architecture}
            maxLength={LIMITS.architecture * 2}
            onChange={(e) => setValues((v) => ({ ...v, architecture: e.target.value }))}
            aria-invalid={errors.architecture ? true : undefined}
            aria-describedby={`${id}-arch-hint ${id}-arch-count${errors.architecture ? ` ${id}-arch-error` : ""}`}
            className={FIELD}
          />
          <p
            id={`${id}-arch-count`}
            className={length > LIMITS.architecture ? "text-destructive text-xs" : "text-muted-foreground text-xs"}
          >
            {length.toLocaleString("en")} / {LIMITS.architecture.toLocaleString("en")} characters
          </p>
          {errors.architecture && (
            <p id={`${id}-arch-error`} className="text-destructive text-xs">
              {errors.architecture}
            </p>
          )}
        </div>
        {failure && (
          <p role="alert" className="text-destructive text-sm">
            {failure}
          </p>
        )}
        <Button type="submit" disabled={saving}>
          {saving ? "Creating…" : "Create threat model"}
        </Button>
      </form>
    </div>
  );
}
