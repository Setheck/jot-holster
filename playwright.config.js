import { defineConfig } from "@playwright/test";

const PORT = 8765;

export default defineConfig({
  testDir: "./tests/ui",
  testMatch: /.*\.spec\.js$/,
  fullyParallel: true,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    viewport: { width: 420, height: 700 },
  },
  webServer: {
    command: `node tests/ui/serve.js ${PORT}`,
    url: `http://127.0.0.1:${PORT}/popup.html`,
    reuseExistingServer: !process.env.CI,
    stdout: "ignore",
    stderr: "pipe",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
