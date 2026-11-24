"use client";

import { useEffect, useId, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { ApiError, fetchScan, uploadScan } from "@/lib/api";
import {
  fileProblem,
  FINISHED,
  MAX_FOLLOW_MS,
  pollDelay,
  type Scan,
  scanOutcome,
  uploadErrorMessage,
} from "@/lib/scans";

// A few failed status checks in a row are a blip; more than this and we stop asking.
const MAX_POLL_FAILURES = 5;

const STATUS_TEXT: Record<Scan["status"], string> = {
  queued: "Waiting for a worker…",
  running: "Checking packages against OSV, EPSS and CISA KEV…",
  done: "Scan finished.",
  failed: "Scan failed.",
};

const TONE = {
  good: "text-foreground",
  warning: "text-amber-700 dark:text-amber-400",
  bad: "text-destructive",
};

type Props = {
  projectId: string;
  /** Called once when a scan finishes, so the page can load the new findings. */
  onScanned: () => void;
  // For tests.
  now?: () => number;
};

export function ScanUpload({ projectId, onScanned, now = Date.now }: Props) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [scan, setScan] = useState<Scan | null>(null);
  const [lost, setLost] = useState<string | null>(null);
  const following = scan !== null && !FINISHED.has(scan.status) && lost === null;

  // Follow the scan until it finishes. Keyed on its id, so a new upload starts afresh.
  const scanId = scan?.id;
  const onScannedRef = useRef(onScanned);
  useEffect(() => {
    onScannedRef.current = onScanned;
  }, [onScanned]);
  useEffect(() => {
    if (!scanId) return;
    const controller = new AbortController();
    const started = now();
    let failures = 0;
    let timer: ReturnType<typeof setTimeout>;

    const check = async () => {
      if (now() - started > MAX_FOLLOW_MS) {
        setLost("This scan is taking unusually long. It carries on; reload the page later to see it.");
        return;
      }
      try {
        const latest = await fetchScan(projectId, scanId, { signal: controller.signal });
        failures = 0;
        setScan(latest);
        if (FINISHED.has(latest.status)) {
          if (latest.status === "done") onScannedRef.current();
          return;
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && (error.kind === "unauthorized" || error.kind === "not-found")) {
          setLost(error.message);
          return;
        }
        failures += 1;
        if (failures >= MAX_POLL_FAILURES) {
          setLost("Lost touch with the scan. It may still finish; reload the page later to see it.");
          return;
        }
      }
      timer = setTimeout(check, pollDelay(now() - started));
    };
    timer = setTimeout(check, pollDelay(0));
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [projectId, scanId, now]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const file = input.current?.files?.[0];
    if (!file) return setProblem("Choose a file first.");
    const local = fileProblem(file);
    if (local) return setProblem(local);
    setProblem(null);
    setLost(null);
    setUploading(true);
    try {
      setScan(await uploadScan(projectId, file));
      if (input.current) input.current.value = "";
    } catch (error) {
      setProblem(uploadErrorMessage(error));
    } finally {
      setUploading(false);
    }
  }

  const outcome = scan && FINISHED.has(scan.status) ? scanOutcome(scan) : null;

  return (
    <div className="rounded-lg border p-4">
      <form onSubmit={submit} noValidate className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <label htmlFor={`${id}-file`} className="block text-sm font-medium">
            Scan a lockfile or SBOM
          </label>
          <input
            id={`${id}-file`}
            ref={input}
            type="file"
            accept=".json,.txt,.yaml,.lock"
            disabled={uploading || following}
            onChange={() => setProblem(null)}
            aria-invalid={problem !== null ? true : undefined}
            aria-describedby={`${id}-hint${problem ? ` ${id}-problem` : ""}`}
            className="block text-sm file:mr-3 file:rounded-md file:border file:bg-background file:px-2.5 file:py-1"
          />
        </div>
        <Button type="submit" size="sm" disabled={uploading || following}>
          {uploading ? "Uploading…" : "Scan"}
        </Button>
      </form>
      <p id={`${id}-hint`} className="text-muted-foreground mt-2 text-xs">
        CycloneDX JSON, requirements.txt, package-lock.json, pnpm-lock.yaml, uv.lock or poetry.lock,
        up to 1 MB. The file is uploaded as it is and deleted after 7 days.
      </p>
      {problem && (
        <p id={`${id}-problem`} role="alert" className="text-destructive mt-2 text-sm">
          {problem}
        </p>
      )}

      <div aria-live="polite" className="mt-2 space-y-2 text-sm">
        {scan && !outcome && lost === null && (
          <p>
            <span className="font-medium">{scan.filename}</span>: {STATUS_TEXT[scan.status]}
          </p>
        )}
        {lost && <p className="text-amber-700 dark:text-amber-400">{lost}</p>}
        {scan && outcome && (
          <p className={TONE[outcome.tone]}>
            <span className="font-medium">{scan.filename}</span>: {outcome.text}
          </p>
        )}
      </div>
      {scan && outcome && scan.skipped > 0 && (
        <details className="mt-2 text-sm">
          <summary className="cursor-pointer">
            {scan.skipped.toLocaleString("en")} {scan.skipped === 1 ? "entry" : "entries"} skipped
          </summary>
          <ul className="text-muted-foreground mt-1 list-disc space-y-0.5 pl-5 text-xs">
            {scan.skipped_examples.map((s, i) => (
              <li key={i}>
                <code>{s.ref}</code>: {s.reason}
              </li>
            ))}
            {scan.skipped > scan.skipped_examples.length && (
              <li>and {(scan.skipped - scan.skipped_examples.length).toLocaleString("en")} more</li>
            )}
          </ul>
        </details>
      )}
    </div>
  );
}
