// =====================================================================
// jot-holster background service worker (ES module)
//
// 1. mirror tokens into declarativeNetRequest dynamic rules — but ONLY
//    when the vault is unlocked (or unencrypted)
// 2. perform oauth2 token fetches on demand; decrypt/re-encrypt as needed
// 3. schedule auto-refresh alarms; alarms quietly skip if vault is locked
// =====================================================================

import { readVault, writeTokens } from "./vault.js";
import { tokenExpiryMs } from "./jwt.js";

const RULE_OFFSET = 1000;
const REFRESH_LEAD_MS = 5 * 60 * 1000;
const TOKEN_FETCH_TIMEOUT_MS = 30_000;

// --- declarativeNetRequest sync ---------------------------------------

function buildRequestHeaders(token) {
  // Extras come first so we can detect a user-supplied Authorization and skip
  // the token-derived one (lets the user override Authorization if they really
  // want to — they were warned about this in the editor).
  const headers = [];
  const seen = new Set();
  for (const h of token.extraHeaders || []) {
    const name = h?.name?.trim();
    if (!name) continue;
    headers.push({ header: name, operation: "set", value: h.value ?? "" });
    seen.add(name.toLowerCase());
  }
  if (token.value && !seen.has("authorization")) {
    headers.push({
      header: "Authorization",
      operation: "set",
      value: `Bearer ${token.value}`,
    });
  }
  return headers;
}

function buildRule(token, index) {
  return {
    id: RULE_OFFSET + index,
    priority: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: buildRequestHeaders(token),
    },
    condition: {
      urlFilter: token.pattern,
      resourceTypes: [
        "main_frame",
        "sub_frame",
        "xmlhttprequest",
        "websocket",
        "other",
      ],
    },
  };
}

async function clearAllDynamicRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  if (!existing.length) return;
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((r) => r.id),
    addRules: [],
  });
}

async function syncRules() {
  const v = await readVault();
  if (v.state === "locked") {
    await clearAllDynamicRules();
    return;
  }
  const enabled = v.tokens.filter((t) => t.enabled && t.value && t.pattern);
  const newRules = enabled.map(buildRule);
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((r) => r.id),
    addRules: newRules,
  });
}

// --- alarms / auto-refresh --------------------------------------------

const BADGE_TICK_ALARM = "badge-tick";

async function scheduleRefreshes() {
  const all = await chrome.alarms.getAll();
  for (const a of all) {
    if (a.name.startsWith("refresh:")) await chrome.alarms.clear(a.name);
  }
  // ensure the periodic badge tick exists
  await chrome.alarms.create(BADGE_TICK_ALARM, { periodInMinutes: 1 });

  const v = await readVault();
  if (v.state === "locked") return;
  for (const t of v.tokens) {
    if (!t.oauth?.autoRefresh || !t.oauth?.tokenUrl) continue;
    const exp = tokenExpiryMs(t);
    if (!exp) continue;
    const at = exp - REFRESH_LEAD_MS;
    if (at > Date.now() + 5000) {
      await chrome.alarms.create(`refresh:${t.id}`, { when: at });
    }
  }
}

// --- badge ------------------------------------------------------------

async function updateBadge() {
  const v = await readVault();
  if (v.state === "locked") {
    await chrome.action.setBadgeText({ text: "" });
    return;
  }
  const now = Date.now();
  const expiredCount = v.tokens.filter((t) => {
    if (!t.enabled) return false;
    const exp = tokenExpiryMs(t);
    return exp && exp <= now;
  }).length;
  if (expiredCount > 0) {
    await chrome.action.setBadgeText({ text: String(expiredCount) });
    await chrome.action.setBadgeBackgroundColor({ color: "#ff5d5d" });
  } else {
    await chrome.action.setBadgeText({ text: "" });
  }
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === BADGE_TICK_ALARM) {
    updateBadge();
    return;
  }
  if (!alarm.name.startsWith("refresh:")) return;
  const id = alarm.name.slice("refresh:".length);
  try {
    await fetchOAuthToken(id);
  } catch (e) {
    console.error("[jot-holster] auto-refresh failed", id, e);
  }
});

// --- oauth2 ------------------------------------------------------------

function randomString(len) {
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  let out = "";
  for (let i = 0; i < len; i++) out += charset[arr[i] % charset.length];
  return out;
}

async function sha256base64url(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function postForm(url, params) {
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") body.set(k, v);
  }
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
    signal: AbortSignal.timeout(TOKEN_FETCH_TIMEOUT_MS),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`token endpoint ${r.status}: ${text.slice(0, 200)}`);
  }
  return r.json();
}

async function flowClientCredentials(c) {
  return postForm(c.tokenUrl, {
    grant_type: "client_credentials",
    client_id: c.clientId,
    client_secret: c.clientSecret,
    scope: c.scope,
    audience: c.audience,
  });
}

async function flowRefreshToken(c) {
  return postForm(c.tokenUrl, {
    grant_type: "refresh_token",
    refresh_token: c.refreshToken,
    client_id: c.clientId,
    client_secret: c.clientSecret,
    scope: c.scope,
  });
}

async function flowAuthorizationCode(c) {
  if (!c.authUrl) throw new Error("authUrl required for authorization_code");
  const verifier = randomString(64);
  const challenge = await sha256base64url(verifier);
  const redirectUri = chrome.identity.getRedirectURL();
  const state = randomString(32);

  const authUrl = new URL(c.authUrl);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", c.clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  if (c.scope) authUrl.searchParams.set("scope", c.scope);
  if (c.audience) authUrl.searchParams.set("audience", c.audience);
  authUrl.searchParams.set("state", state);

  const responseUrl = await chrome.identity.launchWebAuthFlow({
    url: authUrl.toString(),
    interactive: true,
  });
  if (!responseUrl) throw new Error("auth flow cancelled");
  const parsed = new URL(responseUrl);
  const hashParams = new URLSearchParams(parsed.hash.replace(/^#/, ""));
  const error = parsed.searchParams.get("error") || hashParams.get("error");
  if (error) throw new Error(`auth error: ${error}`);
  const returnedState = parsed.searchParams.get("state") || hashParams.get("state");
  if (returnedState !== state) {
    throw new Error("oauth state mismatch — possible csrf, request rejected");
  }
  const code = parsed.searchParams.get("code");
  if (!code) throw new Error("no authorization code in redirect");

  return postForm(c.tokenUrl, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: c.clientId,
    client_secret: c.clientSecret,
    code_verifier: verifier,
  });
}

async function fetchOAuthToken(tokenId) {
  const v = await readVault();
  if (v.state === "locked") throw new Error("vault is locked");
  const t = v.tokens.find((x) => x.id === tokenId);
  if (!t) throw new Error("token not found");
  if (!t.oauth?.tokenUrl) throw new Error("no oauth config");

  const c = t.oauth;
  let result;

  if (c.refreshToken) {
    try {
      result = await flowRefreshToken(c);
    } catch (e) {
      console.warn("[jot-holster] refresh failed, falling back", e.message);
      result = null;
    }
  }
  if (!result) {
    result =
      c.grant === "authorization_code"
        ? await flowAuthorizationCode(c)
        : await flowClientCredentials(c);
  }
  if (!result?.access_token) throw new Error("response had no access_token");

  // re-read in case of concurrent edits
  const latest = await readVault();
  if (latest.state === "locked") throw new Error("vault locked mid-fetch");
  const updated = latest.tokens.map((x) => {
    if (x.id !== tokenId) return x;
    const next = { ...x, value: result.access_token };
    if (result.expires_in) {
      next.expiresAt = Date.now() + Number(result.expires_in) * 1000;
    } else {
      delete next.expiresAt;
    }
    next.oauth = {
      ...x.oauth,
      refreshToken: result.refresh_token || x.oauth.refreshToken,
    };
    return next;
  });
  await writeTokens(updated);
  return { ok: true };
}

// --- message bridge ---------------------------------------------------

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "oauth_fetch") {
    fetchOAuthToken(msg.tokenId)
      .then((r) => sendResponse(r))
      .catch((e) => sendResponse({ error: e.message || String(e) }));
    return true; // async
  }
});

// --- lifecycle hooks --------------------------------------------------

async function reconcile() {
  await syncRules();
  await scheduleRefreshes();
  await updateBadge();
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (
    (area === "local" && (changes.tokens || changes.vault)) ||
    (area === "session" && changes.key)
  ) {
    reconcile();
  }
});

chrome.runtime.onInstalled.addListener(reconcile);
chrome.runtime.onStartup.addListener(reconcile);

// When the user grants (or revokes) host_permissions via the popup, re-run
// the reconcile so newly-eligible tokens get rules and the badge updates,
// rather than waiting until the next storage write.
chrome.permissions.onAdded.addListener(reconcile);
chrome.permissions.onRemoved.addListener(reconcile);
