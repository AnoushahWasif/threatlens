// Serves the static export the way CloudFront does in AWS, for the end-to-end tests: one
// origin, pages and files from out/, and /api/* passed to the API without the prefix. The
// URL rewriting is done by the real CloudFront function files, so they're tested too.
//
// Usage: node e2e/serve.mjs  (PORT, default 3100; API_ORIGIN, default http://127.0.0.1:8765)
import { createReadStream, readFileSync, statSync } from "node:fs";
import { createServer, request as forward } from "node:http";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../out/", import.meta.url));
const functions = fileURLToPath(new URL("../../../infra/functions/", import.meta.url));
const load = (name) =>
  new Function(`${readFileSync(join(functions, name), "utf8")}; return handler;`)();
const viewerRequest = load("viewer-request.js");
const apiRequest = load("api-request.js");

const port = Number(process.env.PORT ?? 3100);
const api = new URL(process.env.API_ORIGIN ?? "http://127.0.0.1:8765");
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".txt": "text/plain; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

function proxy(req, res, path) {
  const upstream = forward(
    { host: api.hostname, port: api.port, method: req.method, path, headers: req.headers },
    (answer) => {
      res.writeHead(answer.statusCode, answer.headers);
      answer.pipe(res);
    },
  );
  upstream.on("error", () => {
    res.writeHead(502).end();
  });
  req.pipe(upstream);
}

createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
    const uri = apiRequest({ request: { uri: url.pathname } }).uri;
    return proxy(req, res, uri + url.search);
  }
  const uri = viewerRequest({ request: { uri: url.pathname, querystring: {}, headers: {} } }).uri;
  let file;
  try {
    file = normalize(join(root, decodeURIComponent(uri)));
  } catch {
    return res.writeHead(400).end(); // a malformed %-escape
  }
  if (!file.startsWith(root.endsWith(sep) ? root : root + sep)) {
    return res.writeHead(403).end();
  }
  try {
    if (!statSync(file).isFile()) throw new Error("not a file");
  } catch {
    // CloudFront may list the bucket, so a missing file is S3's plain 404 (decision 50).
    return res.writeHead(404).end();
  }
  res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
  createReadStream(file).pipe(res);
}).listen(port, "127.0.0.1", () => {
  console.log(`serving out/ on http://127.0.0.1:${port}, /api -> ${api.origin}`);
});
