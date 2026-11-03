// Hashes every inline <script> in the web export, for the CSP's script-src (decision 14).
// The hashes change with every build, so the deploy runs this between `pnpm build` and
// `terraform apply`:
//
//   node infra/scripts/csp-hashes.mjs apps/web/out > infra/web.auto.tfvars.json
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// An inline script: no src attribute. Next's export writes plain <script>...</script>.
const INLINE = /<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/gi;

export function inlineScriptHashes(html) {
  return [...html.matchAll(INLINE)].map(
    (m) => `sha256-${createHash("sha256").update(m[1], "utf8").digest("base64")}`,
  );
}

export function exportHashes(dir) {
  const hashes = new Set();
  let pages = 0;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const path = join(d, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (name.endsWith(".html")) {
        pages += 1;
        for (const h of inlineScriptHashes(readFileSync(path, "utf8"))) hashes.add(h);
      }
    }
  };
  walk(dir);
  if (pages === 0) throw new Error(`no .html files under ${dir}: build the web app first`);
  return [...hashes].sort();
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const dir = process.argv[2];
  if (!dir) {
    console.error("usage: node csp-hashes.mjs <export dir>");
    process.exit(2);
  }
  process.stdout.write(JSON.stringify({ web_script_hashes: exportHashes(dir) }, null, 2) + "\n");
}
