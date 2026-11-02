import { ApiError, type ApiErrorCode } from "@/lib/api-error";
import { LIMITS } from "@/lib/threats";

// Fixed text per error code. The server's own message never reaches the screen.
const BY_CODE: Partial<Record<ApiErrorCode, string>> = {
  not_found: "That threat model doesn't exist, or you don't have access to it.",
  llm_disabled: "AI drafting is turned off on this server. You can still add threats by hand.",
  llm_refused: "The AI declined to draft this one. Add the threats by hand instead.",
  llm_bad_output: "The AI's answer wasn't usable. Try drafting again.",
  llm_busy: "The AI provider is busy. Try again in a minute.",
  llm_unavailable: "Couldn't reach the AI provider. Try again later.",
  too_many_threats: `This model already has the maximum of ${LIMITS.threats} threats. Delete some first.`,
  duplicate_threat: "There's already a threat with this title in this category.",
  draft_in_progress: "A draft for this model is already running. Wait for it to finish.",
  too_many_models: "You've reached the limit of 50 threat models per account.",
  storage_full: "The server has no room for more threat models.",
  validation_error: "The server didn't accept that. Check the fields and try again.",
  payload_too_large: "That's too much text for one request.",
  edit_conflict: "This threat model was changed somewhere else at the same time. Reload and try again.",
  too_large: "This threat model is too big to save. Shorten or remove some threats.",
  storage_busy: "The server is busy. Try again in a moment.",
  storage_unavailable: "The server can't reach its storage right now. Try again later.",
};

export function errorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) return "Something went wrong. Try again.";
  if (error.kind === "not-found") return BY_CODE.not_found!;
  if (error.code === "draft_limit") {
    const minutes = error.retryAfter ? Math.max(1, Math.ceil(error.retryAfter / 60)) : null;
    return minutes
      ? `The hourly limit for AI drafts is used up. Try again in about ${minutes} minute${minutes === 1 ? "" : "s"}.`
      : "The hourly limit for AI drafts is used up. Try again later.";
  }
  return (error.code && BY_CODE[error.code]) ?? error.message;
}
