import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  use: {
    baseURL: process.env.IG_E2E_URL ?? "http://127.0.0.1:8000",
    channel: process.env.IG_E2E_BROWSER,
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
  },
  workers: 1,
});
