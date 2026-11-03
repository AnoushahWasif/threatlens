import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { exportHashes, inlineScriptHashes } from "./csp-hashes.mjs";

const sha = (s) => `sha256-${createHash("sha256").update(s, "utf8").digest("base64")}`;

test("hashes inline scripts only, byte for byte", () => {
  const html =
    '<script src="/_next/a.js"></script><script>self.a=1</script>' +
    '<script async="" src="/b.js"></script><script id="x">\n  é\n</script>';
  assert.deepEqual(inlineScriptHashes(html), [sha("self.a=1"), sha("\n  é\n")]);
});

test("collects unique hashes from every page, nested ones too", () => {
  const dir = mkdtempSync(join(tmpdir(), "csp-"));
  mkdirSync(join(dir, "auth"));
  writeFileSync(join(dir, "index.html"), "<script>a</script><script>b</script>");
  writeFileSync(join(dir, "auth", "callback.html"), "<script>b</script><script>c</script>");
  writeFileSync(join(dir, "index.txt"), "<script>not html</script>");
  assert.deepEqual(exportHashes(dir), [sha("a"), sha("b"), sha("c")].sort());
});

test("an empty or unbuilt export is an error, not an empty allow-list", () => {
  assert.throws(() => exportHashes(mkdtempSync(join(tmpdir(), "csp-"))), /build the web app/);
});
