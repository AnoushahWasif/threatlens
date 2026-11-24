// Run with: node --test infra/functions/
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
// Loaded the way CloudFront runs it: a plain script that defines `handler`, no modules.
const handler = new Function(`${readFileSync(join(here, "viewer-request.js"), "utf8")}; return handler;`)();
const rewrite = (uri) => handler({ request: { uri, querystring: {}, headers: {} } }).uri;

test("clean URLs map to the exported files", () => {
  const cases = {
    "/": "/index.html",
    "/findings": "/findings.html",
    "/findings/": "/findings.html",
    "/auth/callback": "/auth/callback.html",
    "/sign-in": "/sign-in.html",
    "/findings.html": "/findings.html",
    "/favicon.ico": "/favicon.ico",
    "/_next/static/chunks/2bz4th0w2y2ir.css": "/_next/static/chunks/2bz4th0w2y2ir.css",
    "/findings.txt": "/findings.txt",
    "/findings/__next._tree.txt": "/findings/__next._tree.txt",
    "/__next.__PAGE__.txt": "/__next.__PAGE__.txt",
  };
  for (const [uri, expected] of Object.entries(cases)) assert.equal(rewrite(uri), expected, uri);
});

test("Next prefetch paths are rewritten to where the export put them", () => {
  assert.equal(rewrite("/findings/__next.findings.__PAGE__.txt"), "/findings/__next.findings/__PAGE__.txt");
  assert.equal(
    rewrite("/auth/callback/__next.auth.callback.__PAGE__.txt"),
    "/auth/callback/__next.auth/callback/__PAGE__.txt",
  );
});

test("the query string is left alone", () => {
  const out = handler({ request: { uri: "/findings", querystring: { project: { value: "x" } } } });
  assert.deepEqual(out.querystring, { project: { value: "x" } });
});

// Against the real export, when it's been built (apps/web: pnpm build).
const out = join(here, "..", "..", "apps", "web", "out");
test("every page and prefetch file of the real export is reachable", { skip: !existsSync(out) }, () => {
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else files.push("/" + relative(out, path).split(sep).join("/"));
    }
  };
  walk(out);
  const pages = files.filter((f) => f.endsWith(".html") && !f.startsWith("/_not-found"));
  for (const page of pages) {
    const route = page === "/index.html" ? "/" : page.replace(/\.html$/, "");
    assert.ok(files.includes(rewrite(route)), `${route} -> ${rewrite(route)}`);
  }
  // Without prefetch files this test would pass on nothing, so a change in Next's layout
  // must fail it, listing what the export does contain.
  const prefetch = files.filter((f) => f.includes("/__next.") && f.endsWith("__PAGE__.txt"));
  assert.ok(prefetch.length > 0, `no prefetch files in the export:\n${files.join("\n")}`);
  for (const file of prefetch) {
    // Browsers fetch /a/b/__next.a.b.__PAGE__.txt. An export that writes that name as it is
    // must be served as it is; one that writes /a/b/__next.a/b/__PAGE__.txt needs the rewrite.
    const m = file.match(/^(.*?\/)__next\.(.+)\/__PAGE__\.txt$/);
    const requested = m ? `${m[1]}__next.${m[2].split("/").join(".")}.__PAGE__.txt` : file;
    assert.equal(rewrite(requested), file, `${requested}\nprefetch files:\n${prefetch.join("\n")}`);
  }
});
