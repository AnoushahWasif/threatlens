export type ApiErrorKind = "network" | "timeout" | "http" | "invalid" | "not-found" | "unauthorized";

// Messages are fixed strings: nothing from the response is shown to the user.
const MESSAGES: Record<ApiErrorKind, string> = {
  network: "Can't reach the ThreatLens API.",
  timeout: "The ThreatLens API took too long to answer.",
  http: "The ThreatLens API returned an error.",
  invalid: "The ThreatLens API sent data in an unexpected format.",
  "not-found": "That project doesn't exist, or you don't have access to it.",
  unauthorized: "Your session has ended. Sign in again.",
};

// Error codes the UI reacts to. Anything else from the server is treated as a plain "http".
export const KNOWN_CODES = [
  "auth_required",
  "invalid_token",
  "auth_unavailable",
  "too_many_models",
  "not_found",
  "validation_error",
  "payload_too_large",
  "storage_full",
  "too_many_threats",
  "duplicate_threat",
  "draft_in_progress",
  "llm_disabled",
  "draft_limit",
  "llm_refused",
  "llm_bad_output",
  "llm_busy",
  "llm_unavailable",
  "edit_conflict",
  "too_large",
  "too_many_projects",
  "storage_busy",
  "storage_unavailable",
  "write_limit",
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
