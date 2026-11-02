import { z } from "zod";

import { ApiError, type ApiErrorCode, type ApiErrorKind, KNOWN_CODES } from "@/lib/api-error";
import { apiBaseUrl } from "@/lib/config";
import { type Finding, findingListSchema, sampleFindings } from "@/lib/findings";
import { projectListSchema, SAMPLE_PROJECTS, type Project } from "@/lib/projects";
import { sampleThreatModels } from "@/lib/sample-threat-models";
import {
  type DraftResult,
  draftResultSchema,
  type ModelInput,
  type Threat,
  type ThreatInput,
  type ThreatModel,
  threatModelSchema,
  type ThreatPatch,
  threatSchema,
} from "@/lib/threats";

export const TIMEOUT_MS = 10_000;
export const MAX_RESPONSE_BYTES = 2_000_000;

export { ApiError, type ApiErrorCode, type ApiErrorKind, KNOWN_CODES } from "@/lib/api-error";

const MAX_ERROR_BYTES = 4_096;
const MAX_RETRY_AFTER = 3_600;
const errorBodySchema = z.object({ error: z.object({ code: z.string() }) });

export type ProjectsResult = { source: "api" | "sample"; projects: Project[] };

type Options = { baseUrl?: string | null; fetchImpl?: typeof fetch; signal?: AbortSignal };
type Init = { method?: "GET" | "POST" | "PATCH" | "DELETE"; body?: unknown };

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

function getJson<T>(url: string, schema: z.ZodType<T>, options: Options): Promise<T> {
  return request(url, schema, options);
}

async function request<T>(
  url: string,
  schema: z.ZodType<T> | null,
  options: Options,
  init: Init = {},
): Promise<T> {
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
      const hasBody = init.body !== undefined;
      response = await fetchImpl(url, {
        method: init.method ?? "GET",
        signal,
        headers: hasBody
          ? { accept: "application/json", "content-type": "application/json" }
          : { accept: "application/json" },
        body: hasBody ? JSON.stringify(init.body) : undefined,
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
      });
    } catch {
      throw failure("network");
    }

    if (!response.ok) throw await httpError(response);
    if (schema === null) {
      // 204: nothing to read. Cancel the body so the connection is freed.
      await response.body?.cancel().catch(() => undefined);
      return undefined as T;
    }
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

  const parsed = schema!.safeParse(body);
  if (!parsed.success) throw new ApiError("invalid");
  return parsed.data;
}

/** Keeps only the error code (if it's one we know) and a sane Retry-After; never the message. */
async function httpError(response: Response): Promise<ApiError> {
  let code: ApiErrorCode | undefined;
  try {
    if (Number(response.headers.get("content-length") ?? 0) <= MAX_ERROR_BYTES) {
      const text = await response.text();
      if (text.length <= MAX_ERROR_BYTES) {
        const parsed = errorBodySchema.safeParse(JSON.parse(text));
        const raw = parsed.success ? parsed.data.error.code : undefined;
        code = KNOWN_CODES.find((known) => known === raw);
      }
    }
  } catch {
    // An unreadable error body is still an error; the status is enough.
  }
  const header = response.headers.get("retry-after");
  const seconds = header && /^\d{1,6}$/.test(header) ? Number(header) : undefined;
  const retryAfter = seconds === undefined ? undefined : Math.min(seconds, MAX_RETRY_AFTER);
  return new ApiError("http", response.status, code, retryAfter);
}

// --- threat models ----------------------------------------------------------

export type Source = "api" | "sample";

/** The calls the threat-model page makes. Sample mode answers them from memory instead. */
export interface ThreatModelBackend {
  source: Source;
  create(input: ModelInput): Promise<ThreatModel>;
  get(id: string): Promise<ThreatModel>;
  draft(id: string): Promise<DraftResult>;
  addThreat(id: string, input: ThreatInput): Promise<Threat>;
  updateThreat(id: string, threatId: string, patch: ThreatPatch): Promise<Threat>;
  deleteThreat(id: string, threatId: string): Promise<void>;
}

export function threatModelBackend(options: Options = {}): ThreatModelBackend {
  const baseUrl = options.baseUrl === undefined ? apiBaseUrl() : options.baseUrl;
  if (baseUrl === null) return sampleThreatModels;
  const root = `${baseUrl}/threat-models`;
  // Ids come from the address bar or from validated API data; checked again before use in a path.
  const path = (...ids: string[]) => {
    if (!ids.every((id) => UUID.test(id))) throw new ApiError("not-found");
    return ids;
  };
  const call = async <T>(url: string, schema: z.ZodType<T> | null, init?: Init) => {
    try {
      return await request(url, schema, options, init);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        throw new ApiError("not-found", 404, "not_found");
      }
      throw error;
    }
  };
  return {
    source: "api",
    create: (input) => call(root, threatModelSchema, { method: "POST", body: input }),
    get: async (id) => {
      const [m] = path(id);
      return call(`${root}/${m}`, threatModelSchema);
    },
    draft: async (id) => {
      const [m] = path(id);
      return call(`${root}/${m}/draft`, draftResultSchema, { method: "POST" });
    },
    addThreat: async (id, input) => {
      const [m] = path(id);
      return call(`${root}/${m}/threats`, threatSchema, { method: "POST", body: input });
    },
    updateThreat: async (id, threatId, patch) => {
      const [m, t] = path(id, threatId);
      return call(`${root}/${m}/threats/${t}`, threatSchema, { method: "PATCH", body: patch });
    },
    deleteThreat: async (id, threatId) => {
      const [m, t] = path(id, threatId);
      return call(`${root}/${m}/threats/${t}`, null, { method: "DELETE" });
    },
  };
}
