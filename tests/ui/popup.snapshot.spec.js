// Visual snapshot tests. These take a screenshot of the popup in a known
// state and diff it against a baseline PNG. They catch the kind of CSS /
// layout regressions that functional tests miss (e.g. a sticky bar that
// loses its sticky positioning, or a flexbox that collapses).
//
// First run: baselines do not exist; tests fail with "no baseline".
// Generate them with `npx playwright test --update-snapshots` once the UI
// is in a state you're happy with. Subsequent runs compare and fail on
// any pixel diff above the configured threshold.
import { test, expect } from "@playwright/test";

async function loadPopup(page, seed = {}) {
  await page.addInitScript((s) => { window.__seed = s; }, seed);
  await page.addInitScript({ path: "tests/ui/chrome-stubs.js" });
  await page.goto("/popup.html");
  // small settle to let initial refresh() paint
  await page.waitForTimeout(100);
}

const SAMPLE_TOKENS = [
  {
    id: "1",
    name: "staging api",
    env: "staging",
    value:
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
      "eyJzdWIiOiI0MiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9." +
      "x",
    pattern: "https://api.staging.example.com/*",
    enabled: true,
  },
  {
    id: "2",
    name: "prod readonly",
    env: "prod",
    value: "opaque-token-not-a-jwt",
    pattern: "https://api.example.com/*",
    enabled: false,
  },
];

test("empty popup", async ({ page }) => {
  await loadPopup(page);
  await expect(page).toHaveScreenshot("empty-popup.png");
});

test("locked banner", async ({ page }) => {
  await loadPopup(page, {
    local: {
      vault: { version: 1, salt: "AAAA", iterations: 1000, iv: "AAAA", ciphertext: "AAAA" },
    },
  });
  await expect(page).toHaveScreenshot("locked-banner.png");
});

test("token list with sample data", async ({ page }) => {
  await loadPopup(page, { local: { tokens: SAMPLE_TOKENS } });
  await expect(page).toHaveScreenshot("token-list.png");
});

test("editor dialog open", async ({ page }) => {
  await loadPopup(page);
  await page.click("#add-btn");
  await page.waitForTimeout(50);
  await expect(page.locator("#editor")).toHaveScreenshot("editor-dialog.png");
});

test("settings dialog open", async ({ page }) => {
  await loadPopup(page);
  await page.click("#settings-btn");
  await page.waitForTimeout(50);
  await expect(page.locator("#settings-dlg")).toHaveScreenshot("settings-dialog.png");
});
