import { apiBaseUrl } from "@/lib/config";
import { projectListSchema, SAMPLE_PROJECTS, type Project } from "@/lib/projects";

export const TIMEOUT_MS = 10_000;
export const MAX_RESPONSE_BYTES = 2_000_000;

export type ApiErrorKind = "network" | "timeout" | "http" | "invalid";

// Messages are fixed strings: nothing from the response is shown to the user.
const MESSAGES: Record<ApiErrorKind, string> = {
  network: "Can't reach the ThreatLens API.",
  timeout: "The ThreatLens API took too long to answer.",
  http: "The ThreatLens API returned an error.",
  invalid: "The ThreatLens API sent data in an unexpected format.",
};

export class ApiError extends Error {
  constructor(
    readonly kind: ApiErrorKind,
    readonly status?: number,
  ) {
    super(MESSAGES[kind]);
  }
}

export type ProjectsResult = { source: "api" | "sample"; projects: Project[] };

type Options = { baseUrl?: string | null; fetchImpl?: typeof fetch; signal?: AbortSignal };

export async function fetchProjects(options: Options = {}): Promise<ProjectsResult> {
  const baseUrl = options.baseUrl === undefined ? apiBaseUrl() : options.baseUrl;
  if (baseUrl === null) return { source: "sample", projects: SAMPLE_PROJECTS };

  const fetchImpl = options.fetchImpl ?? fetch;
  // One timer for the whole exchange, so a server that sends headers and then stalls
  // the body still times out.
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), TIMEOUT_MS);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout.signal]) : timeout.signal;
  const failure = (fallback: ApiErrorKind) => {
    if (options.signal?.aborted) return options.signal.reason; // the caller cancelled
    return new ApiError(timeout.signal.aborted ? "timeout" : fallback);
  };

  let body: unknown;
  try {
    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}/projects`, {
        signal,
        headers: { accept: "application/json" },
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
      });
    } catch {
      throw failure("network");
    }

    if (!response.ok) throw new ApiError("http", response.status);
    if (Number(response.headers.get("content-length") ?? 0) > MAX_RESPONSE_BYTES) {
      throw new ApiError("invalid");
    }

    let text: string;
    try {
      text = await response.text();
    } catch {
      throw failure("network");
    }
    if (text.length > MAX_RESPONSE_BYTES) throw new ApiError("invalid");
    try {
      body = JSON.parse(text);
    } catch {
      throw new ApiError("invalid");
    }
  } finally {
    clearTimeout(timer);
  }

  const parsed = projectListSchema.safeParse(body);
  if (!parsed.success) throw new ApiError("invalid");
  return { source: "api", projects: parsed.data };
}
