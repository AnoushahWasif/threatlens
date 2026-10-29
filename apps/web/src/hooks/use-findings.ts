"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError, fetchFindings, type FindingsResult } from "@/lib/api";

type State =
  | { status: "loading" }
  | { status: "error"; message: string; notFound: boolean }
  | ({ status: "ready" } & FindingsResult);

const FALLBACK_MESSAGE = "Something went wrong while loading findings.";

/** Mount with `key={projectId}` so a different project starts from "loading". */
export function useFindings(projectId: string) {
  const [state, setState] = useState<State>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    fetchFindings(projectId, { signal: controller.signal }).then(
      (result) => setState({ status: "ready", ...result }),
      (error: unknown) => {
        if (controller.signal.aborted) return;
        // Only our own fixed messages reach the screen, never a raw exception.
        const known = error instanceof ApiError;
        setState({
          status: "error",
          message: known ? error.message : FALLBACK_MESSAGE,
          notFound: known && error.kind === "not-found",
        });
      },
    );
    return () => controller.abort();
  }, [projectId, attempt]);

  const retry = useCallback(() => {
    setState({ status: "loading" });
    setAttempt((n) => n + 1);
  }, []);

  return { state, retry };
}
