"use client";

import { useId, useState } from "react";

import { Button } from "@/components/ui/button";
import { errorMessage } from "@/lib/threat-errors";
import {
  LIMITS,
  STRIDE,
  STRIDE_LABELS,
  type Stride,
  threatErrors,
  type ThreatInput,
  trimThreat,
} from "@/lib/threats";

const FIELD =
  "border-input bg-background w-full rounded-md border px-2.5 py-1.5 text-sm outline-none focus-visible:ring-3 focus-visible:ring-ring/50 aria-invalid:border-destructive";

type Props = {
  initial: ThreatInput;
  submitLabel: string;
  onSubmit: (input: ThreatInput) => Promise<void>;
  onCancel: () => void;
};

export function ThreatForm({ initial, submitLabel, onSubmit, onCancel }: Props) {
  const id = useId();
  const [values, setValues] = useState(initial);
  const [shown, setShown] = useState(false);
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const errors = threatErrors(values);

  const set = (field: keyof ThreatInput) => (e: { target: { value: string } }) =>
    setValues((v) => ({ ...v, [field]: e.target.value }));

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setShown(true);
    if (Object.keys(errors).length > 0) return;
    setSaving(true);
    setFailure(null);
    try {
      await onSubmit(trimThreat(values));
    } catch (error) {
      setFailure(errorMessage(error));
      setSaving(false);
    }
  }

  const field = (name: keyof ThreatInput, label: string, max: number, rows?: number) => {
    const error = shown ? errors[name] : undefined;
    const props = {
      id: `${id}-${name}`,
      value: values[name],
      onChange: set(name),
      "aria-invalid": error ? true : undefined,
      "aria-describedby": error ? `${id}-${name}-error` : undefined,
      className: FIELD,
    };
    return (
      <div className="space-y-1">
        <label htmlFor={props.id} className="text-sm font-medium">
          {label}
        </label>
        {rows ? <textarea rows={rows} maxLength={max * 2} {...props} /> : <input maxLength={max * 2} {...props} />}
        {error && (
          <p id={`${id}-${name}-error`} className="text-destructive text-xs">
            {error}
          </p>
        )}
      </div>
    );
  };

  return (
    <form onSubmit={submit} noValidate className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <label htmlFor={`${id}-category`} className="text-sm font-medium">
            STRIDE category
          </label>
          <select
            id={`${id}-category`}
            value={values.category}
            onChange={(e) => setValues((v) => ({ ...v, category: e.target.value as Stride }))}
            className={FIELD}
          >
            {STRIDE.map((c) => (
              <option key={c} value={c}>
                {STRIDE_LABELS[c]}
              </option>
            ))}
          </select>
        </div>
        {field("component", "Component (optional)", LIMITS.component)}
      </div>
      {field("title", "Title", LIMITS.title)}
      {field("description", "How an attacker would do it", LIMITS.description, 3)}
      {field("mitigation", "Mitigation (optional)", LIMITS.mitigation, 2)}
      {failure && (
        <p role="alert" className="text-destructive text-sm">
          {failure}
        </p>
      )}
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={saving}>
          {saving ? "Saving…" : submitLabel}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
