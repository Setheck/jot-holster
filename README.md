# JWT Vault

A Chrome extension (MV3) that stores JWT/auth tokens, optionally encrypts them with a passphrase, groups them by environment, fetches them via OAuth2, and autofills them as `Authorization: Bearer ...` headers on requests matching a URL pattern.

## Install (unpacked)

1. Unzip the folder.
2. Open `chrome://extensions`.
3. Toggle **Developer mode** (top right).
4. Click **Load unpacked** and select the `jwt-vault` folder.
5. Pin the extension to your toolbar.

## Features

- **Per-token URL pattern + injection** — enabled tokens become `declarativeNetRequest` rules that set the `Authorization` header on matching requests.
- **Environment grouping** — tag each token (or cert) with an env. Rows are grouped by env in the popup; previously-used envs autocomplete.
- **Status indicators** — colored dot per token/cert (green > 1h / 30d, amber, orange, red expired). Toolbar badge shows count of expired enabled tokens, refreshed every minute.
- **JWT decode (inline)** — popup shows header + payload and a live expiry countdown.
- **JWT tools (⚒)** — standalone decode/encode/verify dialog:
  - **Decode** — header, payload, signature, human-readable timestamps for `iat`/`nbf`/`exp`/`auth_time`, plus `iss`/`aud`/`sub`.
  - **Encode** — sign with HS256 (shared secret), RS256, or ES256 (PEM PKCS8 private key).
  - **Verify** — check the signature against a pasted secret/public key/cert, or pick a stored cert from a dropdown. Supports HS256/384/512, RS256/384/512, ES256/384/512.
- **Cert storage** — paste a PEM, get a parsed cert with subject, issuer, validity, public key algorithm, serial, SHA-256 fingerprint, and SANs (DNS / IP / URI / email). No external libraries — uses a small built-in DER parser.
- **OAuth2 fetch** — `client_credentials`, `authorization_code` + PKCE, refresh-token rotation, optional auto-refresh ~5 minutes before expiry. **Auth0 `audience` is supported** in both authorize and token requests.
- **Export / import** — JSON file with both tokens and certs. Merged by ID on import.
- **Encryption (opt-in)** — passphrase-derived AES-GCM-256 (PBKDF2 SHA-256, 600k iterations). Tokens *and* certs are encrypted together. When locked, no header injection, no OAuth fetches.
- **Light & dark theme** — follows your system's `prefers-color-scheme`.

## Storage & encryption

There are three states:

| State | What's in `chrome.storage.local` | What's in `chrome.storage.session` |
|---|---|---|
| Unencrypted (default) | `tokens: [...]` (plaintext) | — |
| Encrypted, locked | `vault: {salt, iterations, iv, ciphertext}` | — |
| Encrypted, unlocked | `vault: {...}` | `key: <JWK>` |

`chrome.storage.session` is in-memory only — never persisted to disk, cleared when Chrome restarts.

### Setting up encryption

1. Click ⚙ → **set up encryption**
2. Pick a passphrase (8+ chars, both fields must match)
3. Tokens are immediately encrypted; the derived key is held in session storage so the popup stays unlocked across reopens until Chrome restarts or you click the lock button (⌧).

### When locked

- The popup shows an unlock screen
- All `declarativeNetRequest` rules are removed (no header injection happens)
- OAuth fetches return an error
- Auto-refresh alarms quietly skip

### Threat model — be honest about it

**Encryption protects against:**
- Someone reading your `chrome.storage.local` data offline (synced profile data, backups, profile theft).
- Casual peeking at storage tools while the vault is locked.

**Encryption does NOT protect against:**
- Code running with access to your Chrome profile while the vault is unlocked (the key sits in session memory).
- Other extensions exploiting Chrome bugs to escape the extension sandbox.
- Forgotten passphrases — there is no recovery.

This is a developer convenience tool, not a password manager. If your tokens are high-stakes (production secrets, customer data), use a real secrets manager.

### Removing encryption

Click ⚙ → **remove encryption**. Tokens are decrypted and written back to plaintext storage; the vault and session key are cleared.

## OAuth2 setup

1. Open a token (or create a new one) and expand **oauth2 fetch**.
2. Tick **configure oauth2** and pick a grant.
3. Fill in the fields (token endpoint, client id, etc).
4. For **authorization code**, copy the **redirect URI** shown in the dialog and register it with your IdP. It looks like `https://<extension-id>.chromiumapp.org/`.
5. Save. A `↻` button appears on the token row — click to fetch.

The popup may close during the auth-code window (Chrome focuses the auth tab); the token still updates in storage. Reopen to see the new value.

## Export / import

- **Export** (`↑`): downloads a JSON file with all tokens including OAuth configs and refresh tokens. **Always plaintext** — exports do not preserve the encrypted form.
- **Import** (`↓`): pick a JSON file. Tokens are matched by `id`: existing IDs are updated, new ones added. Nothing is deleted.

> ⚠️ Treat exports like a `.env` file. They're plaintext.

## How autofill works

Each enabled token becomes one `declarativeNetRequest` dynamic rule:

```
Authorization: Bearer <token.value>
```

applied when the request URL matches `token.pattern`. This covers `fetch`, `XHR`, `WebSocket`, navigation, and subframe requests — no content script touches the page.

## Cross-browser support

| Browser | Status | Work needed |
|---|---|---|
| Chrome 121+ | ✅ tested | none |
| Edge | ✅ works (Chromium) | none — install unpacked the same way |
| Brave / Opera / Vivaldi | ✅ works (Chromium) | none |
| Firefox 121+ | ✅ should work | none — manifest already includes `browser_specific_settings.gecko` and dual `service_worker` + `scripts` background keys |
| Safari 16.4+ | ⚠ needs wrapping | run `xcrun safari-web-extension-converter` on macOS, then build the generated Xcode project and sign it with an Apple Developer account |

### Firefox

Load via `about:debugging` → "This Firefox" → "Load Temporary Add-on…" → pick `manifest.json`. For permanent install you'll need to package and either self-distribute (`web-ext sign`) or submit to AMO.

The `gecko.id` in the manifest is set to a placeholder (`jwt-vault@example.com`) — change it before publishing. Firefox uses `browser.identity.getRedirectURL()` which returns a different URL pattern than Chrome (`https://<uuid>.extensions.allizom.org/` vs Chrome's `https://<id>.chromiumapp.org/`), so the redirect URI shown in the OAuth editor will match whichever browser is running. Register the right one with your IdP.

### Safari

Safari Web Extensions ship as native macOS/iOS apps. Rough flow:

```bash
xcrun safari-web-extension-converter ./jwt-vault
# opens an Xcode project that wraps the extension
# build, sign, and run from Xcode
```

Caveats: iOS Safari has a smaller popup, and `chrome.identity.launchWebAuthFlow` works but must be triggered from a direct user gesture. Distribution requires an Apple Developer account.

### Chromium-specific behaviors to know about

- The `service_worker` key is used by Chrome/Edge/Safari; the `scripts` key is used by Firefox. Including both in one manifest is supported by Chrome 121+ and Firefox 121+. Older browsers will reject the manifest.
- Service worker termination is a Chromium concept. Firefox uses an event-driven background page (similar lifecycle, different internals). Safari's behavior matches Chrome's. Neither difference matters for this extension because all module-scope state is recoverable from `chrome.storage`.



```
jwt-vault/
├── manifest.json     # MV3 manifest (background is type:module)
├── vault.js          # crypto helpers + storage state (tokens + certs)
├── x509.js           # minimal X.509 / ASN.1 DER parser
├── popup.html        # popup UI
├── popup.css         # dark theme + prefers-color-scheme: light override
├── popup.js          # state machine + tools/verify/cert management
├── background.js     # service worker: DNR, OAuth, alarms, badge
└── icons/
```
