import type { z } from "zod";

import { apiBaseUrl } from "@/lib/config";
import { type Finding, findingListSchema, sampleFindings } from "@/lib/findings";
import { projectListSchema, SAMPLE_PROJECTS, type Project } from "@/lib/projects";

export const TIMEOUT_MS = 10_000;
export const MAX_RESPONSE_BYTES = 2_000_000;

export type ApiErrorKind = "network" | "timeout" | "http" | "invalid" | "not-found";

// Messages are fixed strings: nothing from the response is shown to the user.
const MESSAGES: Record<ApiErrorKind, string> = {
  network: "Can't reach the ThreatLens API.",
  timeout: "The ThreatLens API took too long to answer.",
  http: "The ThreatLens API returned an error.",
  invalid: "The ThreatLens API sent data in an unexpected format.",
  "not-found": "That project doesn't exist, or you don't have access to it.",
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

export type FindingsResult = { source: "api" | "sample"; findings: Finding[] };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function fetchProjects(options: Options = {}): Promise<ProjectsResult> {
  const baseUrl = options.baseUrl === undefined ? apiBaseUrl() : options.baseUrl;
  if (baseUrl === null) return { source: "sample", projects: SAMPLE_PROJECTS };
  const projects = await getJson(`${baseUrl}/projects`, projectListSchema, options);
  return { source: "api", projects };
}

export async function fetchFindings(projectId: string, options: Options = {}): Promise<FindingsResult> {
  // The id comes from the address bar, so it's checked before it goes into a URL path.
  if (!UUID.test(projectId)) throw new ApiError("not-found");
  const baseUrl = options.baseUrl === undefined ? apiBaseUrl() : options.baseUrl;
  if (baseUrl === null) {
    const findings = sampleFindings(projectId);
    if (findings === null) throw new ApiError("not-found");
    return { source: "sample", findings };
  }
  try {
    const url = `${baseUrl}/projects/${projectId}/findings`;
    return { source: "api", findings: await getJson(url, findingListSchema, options) };
  } catch (error) {
    // The API answers 404 for "not yours" as well as "doesn't exist", so ids can't be probed.
    if (error instanceof ApiError && error.status === 404) throw new ApiError("not-found", 404);
    throw error;
  }
}

async function getJson<T>(url: string, schema: z.ZodType<T>, options: Options): Promise<T> {
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
      response = await fetchImpl(url, {
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

  const parsed = schema.safeParse(body);
  if (!parsed.success) throw new ApiError("invalid");
  return parsed.data;
}
