import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const handler = new Function(`${readFileSync(join(here, "api-request.js"), "utf8")}; return handler;`)();
const rewrite = (uri) => handler({ request: { uri, querystring: {}, headers: {} } }).uri;

test("strips /api and keeps the rest of the path", () => {
  assert.equal(rewrite("/api/health"), "/health");
  assert.equal(rewrite("/api/projects/abc/scans"), "/projects/abc/scans");
  assert.equal(rewrite("/api/"), "/");
});

test("leaves the method, headers and query string alone", () => {
  const request = {
    uri: "/api/projects",
    method: "POST",
    querystring: { filename: { value: "requirements.txt" } },
    headers: { authorization: { value: "Bearer x" } },
  };
  const out = handler({ request: { ...request } });
  assert.equal(out.method, "POST");
  assert.deepEqual(out.querystring, request.querystring);
  assert.deepEqual(out.headers, request.headers);
});
