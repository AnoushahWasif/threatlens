import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, fetchFindings, fetchProjects, MAX_RESPONSE_BYTES, TIMEOUT_MS } from "@/lib/api";
import { SAMPLE_FINDINGS } from "@/lib/findings";
import { MAX_PROJECTS, SAMPLE_PROJECTS } from "@/lib/projects";

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

  it.each([500, 401, 404])("turns HTTP %i into an http error with the status", async (status) => {
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
