import { readFile } from "node:fs/promises";

import { expect, test, type Page } from "@playwright/test";

const ARCHITECTURE =
  "A Next.js site on CloudFront calls a FastAPI API on Lambda. Users sign in with Cognito. " +
  "Projects live in DynamoDB and uploaded lockfiles in S3; a worker scans them from SQS.";

/**
 * Collects browser errors and failed API calls, so the test fails on anything unexpected.
 * `allowed` lists the failures the journey causes on purpose, as "status path" patterns.
 */
function watch(page: Page, allowed: RegExp[]) {
  const problems: string[] = [];
  page.on("pageerror", (e) => problems.push(`page error: ${e.message}`));
  page.on("console", (m) => {
    // Chrome logs every failed request too; those are checked by status below.
    if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) {
      problems.push(`console: ${m.text()}`);
    }
  });
  page.on("response", (r) => {
    const call = `${r.status()} ${new URL(r.url()).pathname}`;
    if (r.status() >= 400 && !allowed.some((a) => a.test(call))) problems.push(call);
  });
  return problems;
}

async function signIn(page: Page, username: string) {
  await page.goto("/sign-in");
  await page.getByLabel("Username").fill(username);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL("/");
}

test("sign in, build a threat model, export it, scan a lockfile", async ({ page }) => {
  // The scan calls the real OSV, EPSS and KEV services from the worker.
  test.setTimeout(150_000);
  const problems = watch(page, [
    /^503 \/api\/threat-models\/[0-9a-f-]+\/draft$/, // no AI key: drafting is off
    /^404 \/api\/threat-models\/[0-9a-f-]+$/, // bob opening alice's model
    /^422 \/api\/projects\/[0-9a-f-]+\/scans$/, // a file ThreatLens can't read
  ]);

  // Signed out, every page sends you to sign in.
  await page.goto("/threat-model");
  await expect(page).toHaveURL(/\/sign-in/);
  await signIn(page, "alice");
  await expect(page.getByText("No projects yet")).toBeVisible();

  // Threat models are their own thing: a system description and its threats.
  await page.getByRole("link", { name: "Threat model" }).click();
  await page.getByLabel("Name").fill("Shop");
  await page.getByLabel("Architecture description").fill(ARCHITECTURE);
  await page.getByRole("button", { name: "Create threat model" }).click();
  await expect(page).toHaveURL(/\/threat-model\?id=[0-9a-f-]{36}$/);
  const modelUrl = page.url();

  // No AI key in this API: drafting says so in plain words.
  await page.getByRole("button", { name: "Draft with AI" }).click();
  await expect(page.getByText("AI drafting is turned off on this server")).toBeVisible();

  // Nothing accepted yet, so nothing to export.
  await expect(page.getByRole("button", { name: "Export Markdown" })).toBeDisabled();

  // Add a threat by hand.
  await page.getByRole("button", { name: "Add a threat" }).click();
  await page.getByLabel("Title").fill("Stolen session token replayed");
  await page.getByLabel("How an attacker would do it").fill("A token copied from a laptop is used from elsewhere.");
  await page.getByLabel("Mitigation (optional)").fill("Short-lived tokens, revocation on sign-out.");
  await page.getByRole("button", { name: "Add threat" }).click();
  const card = page.getByRole("listitem", { name: "Stolen session token replayed" });
  // Your own threats start accepted. Send it back, then accept it again.
  await expect(card.getByText("Written by hand")).toBeVisible();
  await card.getByRole("button", { name: "Back to review" }).click();
  await expect(page.getByRole("button", { name: "Export Markdown" })).toBeDisabled();
  await card.getByRole("button", { name: "Accept" }).click();
  await expect(card.getByRole("button", { name: "Back to review" })).toBeVisible();

  // The export holds the accepted threat.
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export Markdown" }).click(),
  ]);
  const markdown = await readFile(await download.path(), "utf8");
  expect(markdown).toContain("Stolen session token replayed");
  expect(markdown).toContain("Short-lived tokens");

  // It was saved by the API, not just shown.
  await page.reload();
  await expect(page.getByRole("listitem", { name: "Stolen session token replayed" })).toBeVisible();

  // Projects have no form in the web app yet, so this one is made through the API, the
  // way a script would. It shows in the list and opens its (still empty) findings page.
  const auth = await page.request.post("/api/dev/token", { data: { username: "alice" } });
  const token = (await auth.json()).access_token;
  const created = await page.request.post("/api/projects", {
    data: { name: "Shop backend" },
    headers: { authorization: `Bearer ${token}` },
  });
  expect(created.status()).toBe(201);
  await page.goto("/");
  await page.getByRole("link", { name: "Shop backend" }).click();
  await expect(page).toHaveURL(/\/findings\?project=/);
  await expect(page.getByText("No findings", { exact: true })).toBeVisible();

  // Scanning: an empty file never leaves the browser, a file the API can't read gets a
  // fixed message, and a real one is followed until it finishes.
  const picker = page.getByLabel("Scan a lockfile or SBOM");
  const scan = page.getByRole("button", { name: "Scan", exact: true });
  await picker.setInputFiles({ name: "empty.txt", mimeType: "text/plain", buffer: Buffer.from("") });
  await scan.click();
  await expect(page.getByText("That file is empty.")).toBeVisible();
  await picker.setInputFiles({ name: "notes.md", mimeType: "text/plain", buffer: Buffer.from("hello") });
  await scan.click();
  await expect(page.getByText("ThreatLens couldn't read that file.")).toBeVisible();
  await picker.setInputFiles({
    name: "requirements (1).txt", // tidied to requirements--1-.txt for the API
    mimeType: "text/plain",
    buffer: Buffer.from("jinja2==2.10\nflask>=2.0\n"),
  });
  await scan.click();
  const outcome = page.getByText(/^requirements--1-\.txt: .* in 1 package/);
  await expect(outcome).toBeVisible({ timeout: 120_000 });
  // flask>=2.0 has no exact version, so it's listed as skipped.
  await page.getByText("1 entry skipped").click();
  await expect(page.getByText("not pinned to an exact version")).toBeVisible();
  // If OSV answered, jinja2 2.10's known advisories are now in the table; if it didn't,
  // the outcome says the scan was partial instead of looking clean.
  if (!(await outcome.textContent())?.includes("couldn't be checked")) {
    await expect(page.getByRole("cell", { name: "jinja2" }).first()).toBeVisible();
  }

  // Signing out ends the session; another user sees none of alice's work.
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.goto("/");
  await expect(page).toHaveURL(/\/sign-in/);
  await signIn(page, "bob");
  await expect(page.getByText("No projects yet")).toBeVisible();
  await page.goto(modelUrl);
  await expect(
    page.getByText("That threat model doesn't exist, or you don't have access to it."),
  ).toBeVisible();
  await expect(page.getByText("Stolen session token replayed")).toHaveCount(0);

  expect(problems).toEqual([]);
});
