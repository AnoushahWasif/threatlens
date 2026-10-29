"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError, fetchProjects, type ProjectsResult } from "@/lib/api";

type State =
  | { status: "loading" }
  | { status: "error"; message: string }
  | ({ status: "ready" } & ProjectsResult);

const FALLBACK_MESSAGE = "Something went wrong while loading projects.";

export function useProjects() {
  const [state, setState] = useState<State>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    fetchProjects({ signal: controller.signal }).then(
      (result) => setState({ status: "ready", ...result }),
      (error: unknown) => {
        if (controller.signal.aborted) return;
        // Only our own fixed messages reach the screen, never a raw exception.
        const message = error instanceof ApiError ? error.message : FALLBACK_MESSAGE;
        setState({ status: "error", message });
      },
    );
    return () => controller.abort();
  }, [attempt]);

  const retry = useCallback(() => {
    setState({ status: "loading" });
    setAttempt((n) => n + 1);
  }, []);

  return { state, retry };
}
