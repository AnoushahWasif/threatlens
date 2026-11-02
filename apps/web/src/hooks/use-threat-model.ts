"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError, type Source, type ThreatModelBackend, threatModelBackend } from "@/lib/api";
import { errorMessage } from "@/lib/threat-errors";
import type { Threat, ThreatInput, ThreatModel, ThreatPatch } from "@/lib/threats";

type State =
  | { status: "loading" }
  | { status: "error"; message: string; notFound: boolean }
  | { status: "ready"; source: Source; model: ThreatModel };

/** A bad NEXT_PUBLIC_API_URL throws; that's shown as an error rather than crashing the page. */
export function useBackend(): ThreatModelBackend | null {
  const [backend] = useState(() => {
    try {
      return threatModelBackend();
    } catch {
      return null;
    }
  });
  return backend;
}

/**
 * Loads one threat model and applies changes as the API confirms them: the page only ever
 * shows what the server accepted. Mount with `key={id}`.
 */
export function useThreatModel(id: string) {
  const backend = useBackend();
  const [state, setState] = useState<State>(
    backend ? { status: "loading" } : { status: "error", message: errorMessage(null), notFound: false },
  );
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!backend) return;
    let cancelled = false;
    backend.get(id).then(
      (model) => !cancelled && setState({ status: "ready", source: backend.source, model }),
      (error: unknown) => {
        if (cancelled) return;
        setState({
          status: "error",
          message: errorMessage(error),
          notFound: error instanceof ApiError && error.kind === "not-found",
        });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [backend, id, attempt]);

  const retry = useCallback(() => {
    setState({ status: "loading" });
    setAttempt((n) => n + 1);
  }, []);

  const setModel = useCallback(
    (change: (model: ThreatModel) => ThreatModel) =>
      setState((s) => (s.status === "ready" ? { ...s, model: change(s.model) } : s)),
    [],
  );

  const replaceThreat = (threat: Threat) => (m: ThreatModel) => ({
    ...m,
    threats: m.threats.map((t) => (t.id === threat.id ? threat : t)),
  });

  // These throw ApiError; the caller shows errorMessage(error) next to what failed.
  const actions = {
    draft: async () => {
      const result = await backend!.draft(id);
      setModel(() => result.model);
      return result;
    },
    add: async (input: ThreatInput) => {
      const threat = await backend!.addThreat(id, input);
      setModel((m) => ({ ...m, threats: [...m.threats, threat] }));
    },
    update: async (threatId: string, patch: ThreatPatch) => {
      const threat = await backend!.updateThreat(id, threatId, patch);
      setModel(replaceThreat(threat));
    },
    remove: async (threatId: string) => {
      await backend!.deleteThreat(id, threatId);
      setModel((m) => ({ ...m, threats: m.threats.filter((t) => t.id !== threatId) }));
    },
  };

  return { state, retry, actions };
}
