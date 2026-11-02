export type ApiErrorKind = "network" | "timeout" | "http" | "invalid" | "not-found";

// Messages are fixed strings: nothing from the response is shown to the user.
const MESSAGES: Record<ApiErrorKind, string> = {
  network: "Can't reach the ThreatLens API.",
  timeout: "The ThreatLens API took too long to answer.",
  http: "The ThreatLens API returned an error.",
  invalid: "The ThreatLens API sent data in an unexpected format.",
  "not-found": "That project doesn't exist, or you don't have access to it.",
};

// Error codes the UI reacts to. Anything else from the server is treated as a plain "http".
export const KNOWN_CODES = [
  "not_found",
  "validation_error",
  "payload_too_large",
  "storage_full",
  "too_many_threats",
  "llm_disabled",
  "draft_limit",
  "llm_refused",
  "llm_bad_output",
  "llm_busy",
  "llm_unavailable",
] as const;
export type ApiErrorCode = (typeof KNOWN_CODES)[number];

export class ApiError extends Error {
  constructor(
    readonly kind: ApiErrorKind,
    readonly status?: number,
    readonly code?: ApiErrorCode,
    /** Seconds, from a Retry-After header the server sent with the error. */
    readonly retryAfter?: number,
  ) {
    super(MESSAGES[kind]);
  }
}
