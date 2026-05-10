// Functional smoke tests for the popup UI. Each test loads popup.html with
// stubbed chrome.* APIs and asserts on the rendered DOM. These catch
// behavioral regressions (broken click handlers, missing elements, wrong
// states) but not visual layout issues — see popup.snapshot.spec.js for
// those.
import { test, expect } from "@playwright/test";

async function loadPopup(page, seed = {}, options = {}) {
  await page.addInitScript((s) => { window.__seed = s; }, seed);
  if (options.denyPermissions) {
    await page.addInitScript(() => { window.__permissionsResult = false; });
  }
  await page.addInitScript({ path: "tests/ui/chrome-stubs.js" });
  await page.goto("/popup.html");
  // give popup.js's initial refresh() a tick to run
  await page.waitForFunction(() => !document.body.classList.contains("not-ready"), { timeout: 1000 }).catch(() => {});
}

test.describe("header", () => {
  test("renders six action buttons", async ({ page }) => {
    await loadPopup(page);
    const buttons = page.locator(".hdr-actions button");
    await expect(buttons).toHaveCount(6);
    // lock-btn is hidden when vault is unencrypted
    await expect(page.locator("#lock-btn")).toBeHidden();
    await expect(page.locator("#tools-btn")).toBeVisible();
    await expect(page.locator("#settings-btn")).toBeVisible();
    await expect(page.locator("#add-btn")).toBeVisible();
  });

  test("each header button contains an SVG icon", async ({ page }) => {
    await loadPopup(page);
    const buttons = page.locator(".hdr-actions button:visible");
    const count = await buttons.count();
    for (let i = 0; i < count; i++) {
      await expect(buttons.nth(i).locator("svg.icon")).toHaveCount(1);
    }
  });
});

test.describe("tabs", () => {
  test("renders tokens and certs tabs", async ({ page }) => {
    await loadPopup(page);
    await expect(page.locator(".view-tab")).toHaveCount(2);
    await expect(page.locator('.view-tab[data-view="tokens"]')).toHaveClass(/active/);
  });

  test("clicking certs tab switches the active list", async ({ page }) => {
    await loadPopup(page);
    await page.click('.view-tab[data-view="certs"]');
    await expect(page.locator('.view-tab[data-view="certs"]')).toHaveClass(/active/);
    await expect(page.locator("#cert-list")).toBeVisible();
    await expect(page.locator("#list")).toBeHidden();
  });
});

test.describe("empty state", () => {
  test("shows the empty-state message when there are no tokens", async ({ page }) => {
    await loadPopup(page);
    // the empty-state copy comes from CSS ::after; assert the list is empty
    // and visible (the ::after is what users see)
    await expect(page.locator("#list")).toBeVisible();
    await expect(page.locator("#list .row")).toHaveCount(0);
  });
});

test.describe("locked banner", () => {
  test("banner shows when the vault is locked", async ({ page }) => {
    await loadPopup(page, {
      local: {
        vault: { version: 1, salt: "AAAA", iterations: 1000, iv: "AAAA", ciphertext: "AAAA" },
      },
      session: {}, // no key → locked
    });
    await expect(page.locator("#unlock-form")).toBeVisible();
    await expect(page.locator("#unlock-input")).toBeVisible();
    await expect(page.locator("body.locked")).toHaveCount(1);
  });

  test("banner is hidden for an unencrypted vault", async ({ page }) => {
    await loadPopup(page);
    await expect(page.locator("#unlock-form")).toBeHidden();
  });
});

test.describe("editor dialog", () => {
  test("clicking + opens the editor with bar buttons at top", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    await expect(page.locator("#editor")).toBeVisible();
    const bar = page.locator("#editor .dialog-bar");
    await expect(bar).toBeVisible();
    await expect(bar.locator("#cancel")).toBeVisible();
    await expect(bar.locator("button.primary")).toBeVisible();
    await expect(bar.locator("h2")).toHaveText(/new token/i);
  });

  test("new token defaults to disabled", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    await expect(page.locator('#editor input[name="enabled"]')).not.toBeChecked();
  });

  test("editor has an extra-headers section", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    await expect(page.locator("#extra-headers-section")).toBeVisible();
    // section is collapsed by default — open it to reveal the add-header button
    await page.click("#extra-headers-section summary");
    await expect(page.locator("#add-header-btn")).toBeVisible();
  });

  test("clicking + add header inserts a new row", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    await page.click("#extra-headers-section summary");
    await page.click("#add-header-btn");
    await expect(page.locator("#extra-headers-list .eh-row")).toHaveCount(1);
    await page.click("#add-header-btn");
    await expect(page.locator("#extra-headers-list .eh-row")).toHaveCount(2);
  });

  test("Authorization in extras triggers a warning", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    await page.click("#extra-headers-section summary");
    await page.click("#add-header-btn");
    await page.locator("#extra-headers-list .eh-row .eh-name").last().fill("Authorization");
    await expect(page.locator("#warn-auth-extra")).toBeVisible();
  });

  test("invalid header name triggers a warning", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    await page.click("#extra-headers-section summary");
    await page.click("#add-header-btn");
    await page.locator("#extra-headers-list .eh-row .eh-name").last().fill("X-Has Space");
    await expect(page.locator("#warn-invalid-header")).toBeVisible();
  });

  test("broad URL pattern triggers a warning", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    await page.locator('#editor input[name="pattern"]').fill("https://*/*");
    await expect(page.locator("#warn-pattern")).toBeVisible();
  });

  test("http:// in token endpoint triggers an insecure warning", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    // expand oauth section
    await page.click("#oauth-section summary");
    await page.locator('#editor input[name="tokenUrl"]').fill("http://idp.example.com/oauth/token");
    await expect(page.locator("#warn-token-url")).toBeVisible();
  });

  test("cancel closes the dialog", async ({ page }) => {
    await loadPopup(page);
    await page.click("#add-btn");
    await page.click("#editor #cancel");
    await expect(page.locator("#editor")).toBeHidden();
  });
});

test.describe("settings dialog", () => {
  test("settings opens with bar at top", async ({ page }) => {
    await loadPopup(page);
    await page.click("#settings-btn");
    await expect(page.locator("#settings-dlg")).toBeVisible();
    await expect(page.locator("#settings-dlg .dialog-bar")).toBeVisible();
    await expect(page.locator("#settings-close")).toBeVisible();
  });

  test("close returns to the main popup", async ({ page }) => {
    await loadPopup(page);
    await page.click("#settings-btn");
    await page.click("#settings-close");
    await expect(page.locator("#settings-dlg")).toBeHidden();
  });
});

test.describe("token list rendering", () => {
  // A real-looking JWT (HS256 unsigned-style) — the popup only needs the
  // payload to decode. exp is far in the future.
  const JWT =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiI0MiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9." +
    "x";

  test("renders a token row from seeded storage", async ({ page }) => {
    await loadPopup(page, {
      local: {
        tokens: [
          {
            id: "abc",
            name: "staging api",
            env: "staging",
            value: JWT,
            pattern: "https://api.example.com/*",
            enabled: false,
          },
        ],
      },
    });
    await expect(page.locator(".row")).toHaveCount(1);
    await expect(page.locator(".row .name-text")).toHaveText("staging api");
    await expect(page.locator(".row .pattern")).toContainText("https://api.example.com/*");
    await expect(page.locator(".group-hdr")).toContainText("staging");
  });

  test("eye reveals the decoded JWT claims", async ({ page }) => {
    await loadPopup(page, {
      local: {
        tokens: [
          {
            id: "abc",
            name: "staging api",
            env: "staging",
            value: JWT,
            pattern: "https://api.example.com/*",
            enabled: false,
          },
        ],
      },
    });
    await expect(page.locator(".row .decoded")).toBeHidden();
    await page.click(".row .reveal");
    await expect(page.locator(".row .decoded")).toBeVisible();
    await expect(page.locator(".row .claim-list li")).toContainText(["issued at", "expires", "issuer", "subject"]);
  });

  test("toggling on reverts when host permission is denied", async ({ page }) => {
    await loadPopup(page, {
      local: {
        tokens: [{
          id: "abc",
          name: "staging api",
          env: "staging",
          value: "anything",
          pattern: "https://api.example.com/*",
          enabled: false,
        }],
      },
    }, { denyPermissions: true });
    const toggle = page.locator(".row .toggle");
    await expect(toggle).not.toBeChecked();
    // The checkbox itself is visually hidden behind a styled .slider — click
    // the .switch wrapper (the label), which is the actual hit target.
    await page.locator(".row .switch").click();
    // permission denied → toggle should snap back to off
    await expect(toggle).not.toBeChecked();
  });

  test("eye is hidden when the token is not a JWT", async ({ page }) => {
    await loadPopup(page, {
      local: {
        tokens: [
          {
            id: "abc",
            name: "opaque",
            value: "not-a-jwt",
            pattern: "https://api.example.com/*",
            enabled: false,
          },
        ],
      },
    });
    await expect(page.locator(".row .reveal")).toBeHidden();
  });
});
