import { defineConfig, devices } from "@playwright/test";

// End-to-end: the built site (pnpm build with NEXT_PUBLIC_API_URL=/api) served like
// CloudFront serves it, against the real API in local mode (stand-in sign-in, everything
// in memory, no AI key). See e2e/serve.mjs.
const API_PORT = 8765;
const WEB_PORT = 3100;

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: "retain-on-failure",
    // Locally, an already-downloaded Chromium can stand in for Playwright's own.
    launchOptions: process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {},
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `uv run --directory ../api uvicorn threatlens_api.main:app --host 127.0.0.1 --port ${API_PORT}`,
      url: `http://127.0.0.1:${API_PORT}/health`,
      env: { THREATLENS_AUTH_MODE: "local", THREATLENS_CORS_ORIGINS: "[]" },
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: "node e2e/serve.mjs",
      url: `http://127.0.0.1:${WEB_PORT}/`,
      env: { PORT: String(WEB_PORT), API_ORIGIN: `http://127.0.0.1:${API_PORT}` },
      reuseExistingServer: false,
    },
  ],
});
