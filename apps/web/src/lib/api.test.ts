import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  fetchFindings,
  fetchProjects,
  MAX_RESPONSE_BYTES,
  requestLocalToken,
  threatModelBackend,
  TIMEOUT_MS,
} from "@/lib/api";
import { SAMPLE_FINDINGS } from "@/lib/findings";
import { MAX_PROJECTS, SAMPLE_PROJECTS } from "@/lib/projects";
import { clearSession, readSession, saveSession, SIGNED_OUT_EVENT } from "@/lib/session";

const BASE = "https://api.threatlens.dev";
const PROJECT = {
  id: "0b8f6a52-3c1d-4e9a-8f27-6d5c4b3a2e10",
  name: "payments-service",
  description: "",
  created_at: "2026-10-29T10:00:00.123456+00:00",
};

function respond(body: unknown, init: ResponseInit = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return vi.fn<typeof fetch>().mockResolvedValue(new Response(text, { status: 200, ...init }));
}

async function failure(promise: Promise<unknown>): Promise<ApiError> {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ApiError);
  return error as ApiError;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("fetchProjects", () => {
  it("returns sample data when no API is configured, without a request", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const result = await fetchProjects({ baseUrl: null, fetchImpl });
    expect(result).toEqual({ source: "sample", projects: SAMPLE_PROJECTS });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("parses a valid response from the API", async () => {
    const fetchImpl = respond([PROJECT]);
    const result = await fetchProjects({ baseUrl: BASE, fetchImpl });
    expect(result).toEqual({ source: "api", projects: [PROJECT] });
  });

  it("calls /projects without cookies and refuses redirects", async () => {
    const fetchImpl = respond([]);
    await fetchProjects({ baseUrl: BASE, fetchImpl });
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(`${BASE}/projects`);
    expect(init).toMatchObject({ credentials: "omit", redirect: "error", cache: "no-store" });
  });

  it("drops fields the UI does not know about", async () => {
    const fetchImpl = respond([{ ...PROJECT, owner_email: "someone@example.com" }]);
    const { projects } = await fetchProjects({ baseUrl: BASE, fetchImpl });
    expect(projects[0]).not.toHaveProperty("owner_email");
  });

  it.each([500, 403, 404])("turns HTTP %i into an http error with the status", async (status) => {
    const error = await failure(fetchProjects({ baseUrl: BASE, fetchImpl: respond("{}", { status }) }));
    expect(error.kind).toBe("http");
    expect(error.status).toBe(status);
  });

  it.each([
    ["not JSON", "<html>gateway error</html>"],
    ["an object", { projects: [] }],
    ["a bad id", [{ ...PROJECT, id: "1" }]],
    ["an empty name", [{ ...PROJECT, name: "" }]],
    ["a bad date", [{ ...PROJECT, created_at: "yesterday" }]],
    ["a missing field", [{ id: PROJECT.id, name: "x" }]],
    ["too many projects", Array.from({ length: MAX_PROJECTS + 1 }, () => PROJECT)],
  ])("rejects a response with %s", async (_, body) => {
    const error = await failure(fetchProjects({ baseUrl: BASE, fetchImpl: respond(body) }));
    expect(error.kind).toBe("invalid");
  });

  it("rejects a response that says it is too large before reading it", async () => {
    const fetchImpl = respond([], { headers: { "content-length": String(MAX_RESPONSE_BYTES + 1) } });
    const error = await failure(fetchProjects({ baseUrl: BASE, fetchImpl }));
    expect(error.kind).toBe("invalid");
  });

  it("rejects an oversized body even without a content-length", async () => {
    const fetchImpl = respond("x".repeat(MAX_RESPONSE_BYTES + 1));
    const error = await failure(fetchProjects({ baseUrl: BASE, fetchImpl }));
    expect(error.kind).toBe("invalid");
  });

  it("reports a network failure without leaking the original error", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockRejectedValue(new TypeError("Failed to fetch 10.0.0.5"));
    const error = await failure(fetchProjects({ baseUrl: BASE, fetchImpl }));
    expect(error.kind).toBe("network");
    expect(error.message).not.toContain("10.0.0.5");
  });

  it("times out a request that never answers", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn<typeof fetch>(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    );
    const pending = failure(fetchProjects({ baseUrl: BASE, fetchImpl }));
    await vi.advanceTimersByTimeAsync(TIMEOUT_MS + 1);
    expect((await pending).kind).toBe("timeout");
  });

  it("times out a server that sends headers and then stalls the body", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn<typeof fetch>((_url, init) => {
      const body = new ReadableStream({
        start(controller) {
          init?.signal?.addEventListener("abort", () => controller.error(new DOMException("aborted", "AbortError")));
        },
      });
      return Promise.resolve(new Response(body, { status: 200 }));
    });
    const pending = failure(fetchProjects({ baseUrl: BASE, fetchImpl }));
    await vi.advanceTimersByTimeAsync(TIMEOUT_MS + 1);
    expect((await pending).kind).toBe("timeout");
  });

  it("passes a caller's cancel through instead of calling it an API failure", async () => {
    const controller = new AbortController();
    const fetchImpl = vi.fn<typeof fetch>((_url, init) => {
      controller.abort();
      return Promise.reject(init?.signal?.reason);
    });
    const error = await fetchProjects({ baseUrl: BASE, fetchImpl, signal: controller.signal }).catch((e) => e);
    expect(error).not.toBeInstanceOf(ApiError);
  });
});

describe("fetchFindings", () => {
  const SAMPLE_ID = "3f6c2a1e-8d4b-4c7a-9e21-5b0d7f3a9c11";
  const OTHER_ID = "0b8f6a52-3c1d-4e9a-8f27-6d5c4b3a2e10";

  it.each(["", "not-a-uuid", "../admin", `${OTHER_ID}/../../users`, `${OTHER_ID}?x=1`])(
    "refuses project id %j before any request",
    async (id) => {
      const fetchImpl = vi.fn<typeof fetch>();
      const error = await failure(fetchFindings(id, { baseUrl: BASE, fetchImpl }));
      expect(error.kind).toBe("not-found");
      expect(fetchImpl).not.toHaveBeenCalled();
    },
  );

  it("returns sample findings for the sample project without a request", async () => {
    const result = await fetchFindings(SAMPLE_ID, { baseUrl: null });
    expect(result).toEqual({ source: "sample", findings: SAMPLE_FINDINGS });
  });

  it("treats an unknown project in sample mode as not found", async () => {
    const error = await failure(fetchFindings(OTHER_ID, { baseUrl: null }));
    expect(error.kind).toBe("not-found");
  });

  it("calls the project's findings path and validates the response", async () => {
    const fetchImpl = respond(SAMPLE_FINDINGS);
    const result = await fetchFindings(SAMPLE_ID, { baseUrl: BASE, fetchImpl });
    expect(fetchImpl.mock.calls[0][0]).toBe(`${BASE}/projects/${SAMPLE_ID}/findings`);
    expect(result.findings).toHaveLength(SAMPLE_FINDINGS.length);
  });

  it("turns 404 into not-found (same answer for missing and not yours)", async () => {
    const error = await failure(
      fetchFindings(OTHER_ID, { baseUrl: BASE, fetchImpl: respond("{}", { status: 404 }) }),
    );
    expect(error.kind).toBe("not-found");
  });

  it("keeps other HTTP errors as http errors", async () => {
    const error = await failure(
      fetchFindings(OTHER_ID, { baseUrl: BASE, fetchImpl: respond("{}", { status: 503 }) }),
    );
    expect(error.kind).toBe("http");
  });

  it("rejects a finding with a hostile id", async () => {
    const bad = [{ ...SAMPLE_FINDINGS[0], vuln_id: "javascript:alert(1)" }];
    const error = await failure(fetchFindings(OTHER_ID, { baseUrl: BASE, fetchImpl: respond(bad) }));
    expect(error.kind).toBe("invalid");
  });
});

describe("threatModelBackend", () => {
  const MODEL_ID = "5d2c8b1e-7a4f-4c3d-9e6b-1f0a2d3c4b5e";
  const THREAT_ID = "00000000-0000-4000-8000-000000000001";
  const THREAT = {
    id: THREAT_ID,
    category: "spoofing",
    title: "Forged token",
    description: "Replay a stolen token.",
    mitigation: "",
    component: "API",
    status: "draft",
    source: "llm",
    edited: false,
    created_at: "2026-10-31T09:00:00.123456Z",
    updated_at: "2026-10-31T09:00:00.123456Z",
  };
  const MODEL = {
    id: MODEL_ID,
    name: "payments",
    architecture: "A FastAPI app behind an ALB talks to Stripe and Postgres.",
    threats: [THREAT],
    drafted_with: null,
    drafted_at: null,
    created_at: "2026-10-31T08:00:00Z",
  };
  const api = (fetchImpl: typeof fetch) => threatModelBackend({ baseUrl: BASE, fetchImpl });
  const errorBody = (code: string) => ({ error: { code, message: "server detail", request_id: "abc" } });

  it("uses the in-memory sample backend when no API is configured", () => {
    expect(threatModelBackend({ baseUrl: null }).source).toBe("sample");
  });

  it("creates with a JSON POST, no cookies, no redirects", async () => {
    const fetchImpl = respond(MODEL, { status: 201 });
    const model = await api(fetchImpl).create({ name: "payments", architecture: MODEL.architecture });
    expect(model.id).toBe(MODEL_ID);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(`${BASE}/threat-models`);
    expect(init).toMatchObject({ method: "POST", credentials: "omit", redirect: "error" });
    expect(init?.headers).toMatchObject({ "content-type": "application/json" });
    expect(JSON.parse(String(init?.body))).toEqual({ name: "payments", architecture: MODEL.architecture });
  });

  it("sends PATCH with only the fields given, to the threat's path", async () => {
    const fetchImpl = respond({ ...THREAT, status: "accepted" });
    const threat = await api(fetchImpl).updateThreat(MODEL_ID, THREAT_ID, { status: "accepted" });
    expect(threat.status).toBe("accepted");
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(`${BASE}/threat-models/${MODEL_ID}/threats/${THREAT_ID}`);
    expect(init?.method).toBe("PATCH");
    expect(JSON.parse(String(init?.body))).toEqual({ status: "accepted" });
  });

  it("accepts a 204 with no body for DELETE", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));
    await expect(api(fetchImpl).deleteThreat(MODEL_ID, THREAT_ID)).resolves.toBeUndefined();
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({ method: "DELETE" });
  });

  it("POSTs to /draft with no body and reads the counts", async () => {
    const fetchImpl = respond({ model: MODEL, added: 1, dropped: 2 });
    expect(await api(fetchImpl).draft(MODEL_ID)).toMatchObject({ added: 1, dropped: 2 });
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(`${BASE}/threat-models/${MODEL_ID}/draft`);
    expect(init).toMatchObject({ method: "POST", body: undefined });
    expect(init?.headers).not.toHaveProperty("content-type");
  });

  it.each(["../../admin", "", "5d2c8b1e-7a4f-4c3d-9e6b-1f0a2d3c4b5e/../x"])(
    "refuses id %j without a request",
    async (id) => {
      const fetchImpl = vi.fn<typeof fetch>();
      const error = await failure(api(fetchImpl).get(id));
      expect(error.kind).toBe("not-found");
      expect(fetchImpl).not.toHaveBeenCalled();
    },
  );

  it("turns 404 into not-found", async () => {
    const error = await failure(api(respond(errorBody("not_found"), { status: 404 })).get(MODEL_ID));
    expect(error.kind).toBe("not-found");
  });

  it("keeps a known error code and a capped Retry-After, never the server's message", async () => {
    const fetchImpl = respond(errorBody("draft_limit"), { status: 429, headers: { "retry-after": "99999" } });
    const error = await failure(api(fetchImpl).draft(MODEL_ID));
    expect(error).toMatchObject({ kind: "http", status: 429, code: "draft_limit", retryAfter: 3600 });
    expect(error.message).not.toContain("server detail");
  });

  it.each([
    ["an unknown code", errorBody("drop_tables"), {}],
    ["a non-JSON body", "<html>bad gateway</html>", {}],
    ["an oversized body", errorBody("x".repeat(5_000)), {}],
    ["a bad Retry-After", errorBody("llm_busy"), { "retry-after": "soon" }],
  ])("copes with %s", async (_name, body, headers) => {
    const error = await failure(api(respond(body, { status: 503, headers })).draft(MODEL_ID));
    expect(error.kind).toBe("http");
    expect(error.retryAfter).toBeUndefined();
    if (_name !== "a bad Retry-After") expect(error.code).toBeUndefined();
  });

  it("rejects a draft result with nonsense counts", async () => {
    const fetchImpl = respond({ model: MODEL, added: -1, dropped: 0 });
    expect((await failure(api(fetchImpl).draft(MODEL_ID))).kind).toBe("invalid");
  });

  it("rejects a threat model that doesn't match the schema", async () => {
    const bad = { ...MODEL, threats: [{ ...THREAT, category: "phishing" }] };
    expect((await failure(api(respond(bad)).get(MODEL_ID))).kind).toBe("invalid");
  });
});


describe("auth on API calls", () => {
  const TOKEN = "header.eyJleHAiOjk5OTk5OTk5OTl9.signature-xyz";

  beforeEach(() => {
    clearSession();
  });

  it("sends the session's access token as a bearer token", async () => {
    saveSession({ accessToken: TOKEN, username: "alice", expiresAt: Date.now() + 3_600_000 });
    const fetchImpl = respond([]);
    await fetchProjects({ baseUrl: BASE, fetchImpl });
    expect(fetchImpl.mock.calls[0][1]?.headers).toMatchObject({ authorization: `Bearer ${TOKEN}` });
  });

  it("sends no Authorization header when signed out, and never a cookie", async () => {
    const fetchImpl = respond([]);
    await fetchProjects({ baseUrl: BASE, fetchImpl });
    expect(fetchImpl.mock.calls[0][1]?.headers).not.toHaveProperty("authorization");
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({ credentials: "omit" });
  });

  it("ends the session on 401 and tells the app", async () => {
    saveSession({ accessToken: TOKEN, username: "alice", expiresAt: Date.now() + 3_600_000 });
    const listener = vi.fn();
    window.addEventListener(SIGNED_OUT_EVENT, listener);
    const body = { error: { code: "invalid_token", message: "x", request_id: "r" } };
    const error = await failure(fetchProjects({ baseUrl: BASE, fetchImpl: respond(body, { status: 401 }) }));
    window.removeEventListener(SIGNED_OUT_EVENT, listener);
    expect(error).toMatchObject({ kind: "unauthorized", status: 401, code: "invalid_token" });
    expect(error.message).toBe("Your session has ended. Sign in again.");
    expect(readSession()).toBeNull();
    expect(listener).toHaveBeenCalledOnce();
  });

  it("asks the dev token route without sending any existing token", async () => {
    saveSession({ accessToken: TOKEN, username: "alice", expiresAt: Date.now() + 3_600_000 });
    const fetchImpl = respond({ access_token: "a".repeat(40), token_type: "Bearer", expires_in: 3600 });
    const result = await requestLocalToken("bob", { baseUrl: BASE, fetchImpl });
    expect(result.expires_in).toBe(3600);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(`${BASE}/dev/token`);
    expect(init?.headers).not.toHaveProperty("authorization");
    expect(JSON.parse(String(init?.body))).toEqual({ username: "bob" });
  });
});
