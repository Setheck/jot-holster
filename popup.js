import {
  VAULT_VERSION,
  KDF_ITERATIONS,
  b64enc,
  b64dec,
  randomSalt,
  deriveKey,
  encryptObject,
  exportJWK,
  readVault,
  writeTokens,
  writeCerts,
} from "./vault.js";
import { parseCertificate, spkiFromCertPem, spkiFromPublicKeyPem } from "./x509.js";
import { decodeJwt, expInfo, statusClass } from "./jwt.js";
import { isBroadPattern, isInsecureUrl, isValidHeaderName } from "./validation.js";

const $ = (s, r = document) => r.querySelector(s);

const unlockForm = $("#unlock-form");
const unlockInput = $("#unlock-input");
const unlockErr = $("#unlock-err");

const list = $("#list");
const certList = $("#cert-list");
const tpl = $("#row-tpl");
const certTpl = $("#cert-tpl");
const dlg = $("#editor");
const form = $("#form");
const formTitle = $("#form-title");
const certDlg = $("#cert-editor");
const certForm = $("#cert-form");
const certFormTitle = $("#cert-form-title");
const certCancelBtn = $("#cert-cancel");
const certErr = $("#cert-err");
const addBtn = $("#add-btn");
const cancelBtn = $("#cancel");
const exportBtn = $("#export-btn");
const importBtn = $("#import-btn");
const importFile = $("#import-file");
const settingsBtn = $("#settings-btn");
const lockBtn = $("#lock-btn");
const envSuggestions = $("#env-suggestions");
const oauthSection = $("#oauth-section");
const oauthFields = $(".oauth-fields");
const grantSelect = form.elements.grant;
const redirectUriEl = $("#redirect-uri");
const copyRedirectBtn = $("#copy-redirect");
const viewTabs = document.querySelectorAll(".view-tab");

const settingsDlg = $("#settings-dlg");
const settingsClose = $("#settings-close");
const encUnencrypted = $("#enc-unencrypted");
const encUnlocked = $("#enc-unlocked");
const setupEncryptionBtn = $("#setup-encryption");
const changePassBtn = $("#change-passphrase");
const disableEncryptionBtn = $("#disable-encryption");

const passDlg = $("#pass-dlg");
const passForm = $("#pass-form");
const passTitle = $("#pass-title");
const passConfirmRow = $("#pass-confirm-row");
const passWarn = $("#pass-warn");
const passErr = $("#pass-err");
const passCancelBtn = $("#pass-cancel");

const uid = () => Math.random().toString(36).slice(2, 10);

let currentState = { state: "unencrypted", tokens: [], certs: [] };
let currentView = "tokens"; // or "certs"

// ---- render ----
function applyChrome() {
  const locked = currentState.state === "locked";
  document.body.classList.toggle("locked", locked);
  unlockForm.hidden = !locked;
  list.hidden = currentView !== "tokens";
  certList.hidden = currentView !== "certs";

  // disable unrelated buttons when locked
  for (const b of [addBtn, exportBtn, importBtn, settingsBtn]) b.disabled = locked;
  lockBtn.hidden = currentState.state !== "unlocked";

  // + button context-aware
  addBtn.title = currentView === "certs" ? "Add cert" : "Add token";

  // active tab
  for (const t of viewTabs) t.classList.toggle("active", t.dataset.view === currentView);

  if (locked) setTimeout(() => unlockInput.focus(), 0);
}

function certStatus(c) {
  const exp = Date.parse(c.notAfter || "");
  if (isNaN(exp)) return "unknown";
  const ms = exp - Date.now();
  if (ms <= 0) return "expired";
  if (ms < 7 * 86400000) return "urgent";
  if (ms < 30 * 86400000) return "warn";
  return "healthy";
}

function certExpInfo(c) {
  const exp = Date.parse(c.notAfter || "");
  if (isNaN(exp)) return { text: "", expired: false };
  const ms = exp - Date.now();
  if (ms <= 0) return { text: " · expired", expired: true };
  const d = Math.floor(ms / 86400000);
  if (d > 365) return { text: ` · ${Math.floor(d / 365)}y ${d % 365}d left`, expired: false };
  if (d > 30) return { text: ` · ${Math.floor(d / 30)}mo ${d % 30}d left`, expired: false };
  if (d > 0) return { text: ` · ${d}d left`, expired: false };
  const h = Math.floor((ms / 3600000) % 24);
  return { text: ` · ${h}h left`, expired: false };
}

function fmtDate(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").replace(/\..*$/, " UTC");
}

function renderCerts() {
  certList.innerHTML = "";
  if (currentState.state === "locked") return;
  const certs = currentState.certs || [];

  // group by env
  const groups = new Map();
  for (const c of certs) {
    const k = (c.env || "").trim() || "—";
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(c);
  }
  const sorted = [...groups.entries()].sort(([a], [b]) => {
    if (a === "—") return 1;
    if (b === "—") return -1;
    return a.localeCompare(b);
  });

  for (const [env, cs] of sorted) {
    const h = document.createElement("h3");
    h.className = "group-hdr";
    h.textContent = env;
    certList.append(h);
    for (const c of cs) {
      const node = certTpl.content.cloneNode(true);
      const row = node.querySelector(".row");
      row.dataset.id = c.id;

      node.querySelector(".name-text").textContent = c.name;
      node.querySelector(".status-dot").classList.add(certStatus(c));

      const exp = certExpInfo(c);
      const subEl = node.querySelector(".cert-sub");
      const cn = c.subjectRdns?.find((r) => r.name === "CN")?.value || c.subject || "(no subject)";
      subEl.textContent = cn + exp.text;
      if (exp.expired) subEl.classList.add("expired");

      node.querySelector(".ci-subject").textContent = c.subject || "—";
      node.querySelector(".ci-issuer").textContent = c.issuer || "—";

      const fromEl = node.querySelector(".ci-from");
      fromEl.textContent = fmtDate(c.notBefore);

      const toEl = node.querySelector(".ci-to");
      toEl.textContent = fmtDate(c.notAfter);
      const status = certStatus(c);
      if (status !== "healthy" && status !== "unknown") toEl.classList.add(status);

      node.querySelector(".ci-alg").textContent = c.publicKeyAlgorithm || "—";
      node.querySelector(".ci-serial").textContent = c.serialNumber || "—";
      node.querySelector(".ci-fp").textContent = c.fingerprint || "—";

      const sanRow = node.querySelector(".ci-san-row");
      const sanDd = node.querySelector(".ci-san");
      const sanParts = [];
      if (c.sans?.dnsNames?.length) sanParts.push(...c.sans.dnsNames.map((d) => `DNS:${d}`));
      if (c.sans?.ipAddresses?.length) sanParts.push(...c.sans.ipAddresses.map((d) => `IP:${d}`));
      if (c.sans?.uris?.length) sanParts.push(...c.sans.uris.map((d) => `URI:${d}`));
      if (c.sans?.emails?.length) sanParts.push(...c.sans.emails.map((d) => `email:${d}`));
      if (sanParts.length) {
        sanDd.textContent = sanParts.join(", ");
      } else {
        sanRow.style.display = "none";
        sanDd.style.display = "none";
      }

      certList.append(node);
    }
  }
}

function renderActive() {
  if (currentView === "certs") renderCerts();
  else renderList();
  populateVerifyCertSelect();
}

function renderList() {
  list.innerHTML = "";
  if (currentState.state === "locked") return;
  const tokens = currentState.tokens;

  // group by env
  const groups = new Map();
  for (const t of tokens) {
    const k = (t.env || "").trim() || "—";
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(t);
  }
  const sorted = [...groups.entries()].sort(([a], [b]) => {
    if (a === "—") return 1;
    if (b === "—") return -1;
    return a.localeCompare(b);
  });

  for (const [env, ts] of sorted) {
    const h = document.createElement("h3");
    h.className = "group-hdr";
    h.textContent = env;
    list.append(h);
    for (const t of ts) {
      const node = tpl.content.cloneNode(true);
      const row = node.querySelector(".row");
      row.dataset.id = t.id;

      node.querySelector(".name-text").textContent = t.name;
      node.querySelector(".status-dot").classList.add(statusClass(t));

      const exp = expInfo(t);
      const patternEl = node.querySelector(".pattern");
      patternEl.textContent = t.pattern + exp.text;
      if (exp.expired) patternEl.classList.add("expired");

      node.querySelector(".toggle").checked = !!t.enabled;

      const refreshBtn = node.querySelector(".refresh");
      if (!t.oauth?.tokenUrl) refreshBtn.classList.add("hidden");

      const revealBtn = node.querySelector(".reveal");
      const decoded = t.value ? decodeJwt(t.value) : null;
      if (decoded) {
        populateClaimList(node.querySelector(".claim-list"), decoded);
        node.querySelector(".decoded-json").textContent =
          JSON.stringify(decoded, null, 2);
      } else {
        // Either no value at all, or an opaque (non-JWT) token. The eye is only
        // useful when there is something decodable to show.
        revealBtn.classList.add("hidden");
      }
      list.append(node);
    }
  }

  // env suggestions
  envSuggestions.innerHTML = "";
  const envs = new Set(tokens.map((t) => t.env).filter(Boolean));
  for (const e of envs) {
    const opt = document.createElement("option");
    opt.value = e;
    envSuggestions.append(opt);
  }
}

async function refresh() {
  currentState = await readVault();
  applyChrome();
  renderActive();
}

function flash(msg, isError = false) {
  const el = document.createElement("div");
  el.className = "flash" + (isError ? " error" : "");
  el.textContent = msg;
  document.body.append(el);
  setTimeout(() => el.remove(), 1800);
}

// ---- unlock ----
unlockForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  unlockErr.textContent = "";
  const passphrase = unlockInput.value;
  const { vault } = await chrome.storage.local.get("vault");
  if (!vault) {
    unlockErr.textContent = "no vault found";
    return;
  }
  try {
    const salt = b64dec(vault.salt);
    const key = await deriveKey(passphrase, salt, vault.iterations);
    const jwk = await exportJWK(key);
    // verify by attempting decrypt before storing
    await chrome.storage.session.set({ key: jwk });
    const next = await readVault();
    if (next.state !== "unlocked") {
      await chrome.storage.session.remove("key");
      throw new Error("incorrect passphrase");
    }
    unlockInput.value = "";
    currentState = next;
    applyChrome();
    renderActive();
    flash("unlocked");
  } catch (err) {
    unlockErr.textContent = err.message || "unlock failed";
  }
});

// ---- lock ----
lockBtn.addEventListener("click", async () => {
  await chrome.storage.session.remove("key");
  await refresh();
  flash("locked");
});

// ---- editor ----
function applyOAuthVisibility() {
  const grant = grantSelect.value;
  if (grant === "authorization_code") oauthFields.classList.add("show-auth");
  else oauthFields.classList.remove("show-auth");
}

grantSelect.addEventListener("change", applyOAuthVisibility);

const warnPattern = $("#warn-pattern");
const warnTokenUrl = $("#warn-token-url");
const warnAuthUrl = $("#warn-auth-url");
const warnAuthExtra = $("#warn-auth-extra");
const warnInvalidHeader = $("#warn-invalid-header");

const headerRowTpl = $("#header-row-tpl");
const extraHeadersList = $("#extra-headers-list");
const extraHeadersSection = $("#extra-headers-section");
const addHeaderBtn = $("#add-header-btn");

function addHeaderRow(name = "", value = "") {
  const node = headerRowTpl.content.cloneNode(true);
  node.querySelector(".eh-name").value = name;
  node.querySelector(".eh-value").value = value;
  extraHeadersList.append(node);
}

addHeaderBtn.addEventListener("click", () => {
  addHeaderRow();
  applyEditorWarnings();
  // focus the new name input
  const last = extraHeadersList.lastElementChild?.querySelector(".eh-name");
  last?.focus();
});

extraHeadersList.addEventListener("click", (e) => {
  const removeBtn = e.target.closest(".eh-remove");
  if (!removeBtn) return;
  removeBtn.closest(".eh-row")?.remove();
  applyEditorWarnings();
});

extraHeadersList.addEventListener("input", (e) => {
  if (e.target.classList.contains("eh-name")) applyEditorWarnings();
});

function applyEditorWarnings() {
  warnPattern.hidden = !isBroadPattern(form.elements.pattern.value);
  warnTokenUrl.hidden = !isInsecureUrl(form.elements.tokenUrl.value);
  warnAuthUrl.hidden = !isInsecureUrl(form.elements.authUrl.value);

  let authOverride = false;
  let invalidName = false;
  for (const row of extraHeadersList.querySelectorAll(".eh-row")) {
    const name = row.querySelector(".eh-name").value.trim();
    if (!name) continue;
    if (name.toLowerCase() === "authorization") authOverride = true;
    if (!isValidHeaderName(name)) invalidName = true;
  }
  warnAuthExtra.hidden = !authOverride;
  warnInvalidHeader.hidden = !invalidName;
}

for (const el of [form.elements.pattern, form.elements.tokenUrl, form.elements.authUrl]) {
  el.addEventListener("input", applyEditorWarnings);
}

function openEditor(t = null) {
  formTitle.textContent = t ? "edit token" : "new token";
  form.elements.id.value = t?.id || "";
  form.elements.name.value = t?.name || "";
  form.elements.env.value = t?.env || "";
  form.elements.value.value = t?.value || "";
  form.elements.pattern.value = t?.pattern || "";
  // New tokens default to disabled — the user has to opt in to header injection
  // after they've set the URL pattern.
  form.elements.enabled.checked = !!t?.enabled;

  const o = t?.oauth || {};
  form.elements.oauthEnabled.checked = !!t?.oauth;
  form.elements.grant.value = o.grant || "client_credentials";
  form.elements.tokenUrl.value = o.tokenUrl || "";
  form.elements.authUrl.value = o.authUrl || "";
  form.elements.clientId.value = o.clientId || "";
  form.elements.clientSecret.value = o.clientSecret || "";
  form.elements.scope.value = o.scope || "";
  form.elements.audience.value = o.audience || "";
  form.elements.autoRefresh.checked = !!o.autoRefresh;

  // extra headers
  extraHeadersList.replaceChildren();
  for (const h of t?.extraHeaders || []) {
    addHeaderRow(h.name || "", h.value || "");
  }
  extraHeadersSection.open = !!(t?.extraHeaders?.length);

  oauthSection.open = !!t?.oauth;
  applyOAuthVisibility();
  applyEditorWarnings();
  redirectUriEl.textContent = chrome.identity.getRedirectURL();

  dlg.showModal();
}

addBtn.addEventListener("click", () => {
  if (currentView === "certs") openCertEditor();
  else openEditor();
});
cancelBtn.addEventListener("click", () => dlg.close());

// view tab switching
for (const tab of viewTabs) {
  tab.addEventListener("click", () => {
    currentView = tab.dataset.view;
    applyChrome();
    renderActive();
  });
}

copyRedirectBtn.addEventListener("click", async () => {
  await navigator.clipboard.writeText(redirectUriEl.textContent);
  flash("redirect uri copied");
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = form.elements;
  const data = {
    id: f.id.value || uid(),
    name: f.name.value.trim(),
    env: f.env.value.trim(),
    value: f.value.value.trim(),
    pattern: f.pattern.value.trim(),
    enabled: f.enabled.checked,
  };
  if (f.oauthEnabled.checked) {
    data.oauth = {
      grant: f.grant.value,
      tokenUrl: f.tokenUrl.value.trim(),
      authUrl: f.authUrl.value.trim(),
      clientId: f.clientId.value.trim(),
      clientSecret: f.clientSecret.value,
      scope: f.scope.value.trim(),
      audience: f.audience.value.trim(),
      autoRefresh: f.autoRefresh.checked,
    };
    const existing = currentState.tokens.find((t) => t.id === data.id);
    if (existing?.oauth?.refreshToken) {
      data.oauth.refreshToken = existing.oauth.refreshToken;
    }
  }
  // collect extra headers — drop rows with empty names
  const extraHeaders = [];
  for (const row of extraHeadersList.querySelectorAll(".eh-row")) {
    const name = row.querySelector(".eh-name").value.trim();
    const value = row.querySelector(".eh-value").value;
    if (name) extraHeaders.push({ name, value });
  }
  if (extraHeaders.length) data.extraHeaders = extraHeaders;

  if (!data.value && !data.oauth?.tokenUrl) {
    flash("need a token or an oauth config", true);
    return;
  }
  const tokens = [...currentState.tokens];
  const idx = tokens.findIndex((t) => t.id === data.id);
  if (idx >= 0 && tokens[idx].value === data.value && tokens[idx].expiresAt) {
    data.expiresAt = tokens[idx].expiresAt;
  }
  if (idx >= 0) tokens[idx] = data;
  else tokens.push(data);
  await writeTokens(tokens);
  dlg.close();
});

// ---- cert editor ----
function openCertEditor(c = null) {
  certFormTitle.textContent = c ? "edit cert" : "add cert";
  certForm.elements.id.value = c?.id || "";
  certForm.elements.name.value = c?.name || "";
  certForm.elements.env.value = c?.env || "";
  certForm.elements.pem.value = c?.pem || "";
  certErr.textContent = "";
  certDlg.showModal();
}

certCancelBtn.addEventListener("click", () => certDlg.close());

certForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  certErr.textContent = "";
  const f = certForm.elements;
  const pem = f.pem.value.trim();
  const id = f.id.value || uid();
  const name = f.name.value.trim();
  const env = f.env.value.trim();
  if (!pem) {
    certErr.textContent = "PEM required";
    return;
  }
  let parsed;
  try {
    parsed = await parseCertificate(pem);
  } catch (err) {
    certErr.textContent = "could not parse: " + err.message;
    return;
  }
  const cert = { id, name, env, pem, ...parsed };
  const certs = [...(currentState.certs || [])];
  const idx = certs.findIndex((c) => c.id === id);
  if (idx >= 0) certs[idx] = cert;
  else certs.push(cert);
  await writeCerts(certs);
  certDlg.close();
});

// cert row actions
certList.addEventListener("click", async (e) => {
  const row = e.target.closest(".row");
  if (!row) return;
  const id = row.dataset.id;
  const certs = [...(currentState.certs || [])];
  const idx = certs.findIndex((c) => c.id === id);
  if (idx < 0) return;

  if (e.target.classList.contains("copy-pem")) {
    await navigator.clipboard.writeText(certs[idx].pem);
    flash("PEM copied");
  } else if (e.target.classList.contains("cert-del")) {
    if (!confirm(`delete "${certs[idx].name}"?`)) return;
    certs.splice(idx, 1);
    await writeCerts(certs);
  } else if (e.target.classList.contains("cert-edit")) {
    openCertEditor(certs[idx]);
  }
});

// ---- row actions (tokens) ----
list.addEventListener("click", async (e) => {
  const row = e.target.closest(".row");
  if (!row) return;
  const id = row.dataset.id;
  const tokens = [...currentState.tokens];
  const idx = tokens.findIndex((t) => t.id === id);
  if (idx < 0) return;

  if (e.target.classList.contains("reveal")) {
    const decodedEl = row.querySelector(".decoded");
    const wasRevealed = !decodedEl.hidden;
    decodedEl.hidden = wasRevealed;
    e.target.classList.toggle("revealed", !wasRevealed);
    e.target.title = wasRevealed ? "Show decoded JWT" : "Hide decoded JWT";
  } else if (e.target.classList.contains("copy")) {
    if (!tokens[idx].value) {
      flash("no token value", true);
      return;
    }
    await navigator.clipboard.writeText(tokens[idx].value);
    flash("copied");
  } else if (e.target.classList.contains("del")) {
    if (!confirm(`delete "${tokens[idx].name}"?`)) return;
    tokens.splice(idx, 1);
    await writeTokens(tokens);
  } else if (e.target.classList.contains("edit")) {
    openEditor(tokens[idx]);
  } else if (e.target.classList.contains("refresh")) {
    e.target.classList.add("loading");
    flash("fetching...");
    try {
      const res = await chrome.runtime.sendMessage({ type: "oauth_fetch", tokenId: id });
      if (res?.error) flash(res.error, true);
      else flash("token refreshed");
    } catch (err) {
      flash(err.message || "fetch failed", true);
    } finally {
      e.target.classList.remove("loading");
    }
  }
});

list.addEventListener("change", async (e) => {
  if (!e.target.classList.contains("toggle")) return;
  const id = e.target.closest(".row").dataset.id;
  const tokens = [...currentState.tokens];
  const t = tokens.find((t) => t.id === id);
  if (t) {
    t.enabled = e.target.checked;
    await writeTokens(tokens);
  }
});

// ---- export ----
exportBtn.addEventListener("click", async () => {
  if (currentState.state === "locked") return;
  const blob = new Blob(
    [JSON.stringify(
      {
        version: 2,
        exportedAt: new Date().toISOString(),
        tokens: currentState.tokens,
        certs: currentState.certs || [],
      },
      null, 2
    )],
    { type: "application/json" }
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `token-manager-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  flash("exported (plaintext)");
});

// ---- import ----
importBtn.addEventListener("click", () => {
  if (currentState.state === "locked") return;
  importFile.click();
});

importFile.addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    if (!Array.isArray(data?.tokens) && !Array.isArray(data?.certs)) {
      throw new Error("invalid format");
    }

    let added = 0, updated = 0;

    if (Array.isArray(data.tokens)) {
      const byId = new Map(currentState.tokens.map((t) => [t.id, t]));
      for (const t of data.tokens) {
        if (!t.id || !t.name) continue;
        if (byId.has(t.id)) {
          byId.set(t.id, { ...byId.get(t.id), ...t });
          updated++;
        } else {
          byId.set(t.id, t);
          added++;
        }
      }
      await writeTokens([...byId.values()]);
    }

    if (Array.isArray(data.certs)) {
      const byId = new Map((currentState.certs || []).map((c) => [c.id, c]));
      for (const c of data.certs) {
        if (!c.id || !c.name) continue;
        if (byId.has(c.id)) {
          byId.set(c.id, { ...byId.get(c.id), ...c });
          updated++;
        } else {
          byId.set(c.id, c);
          added++;
        }
      }
      await writeCerts([...byId.values()]);
    }

    flash(`imported: ${added} added, ${updated} updated`);
  } catch (err) {
    flash("import failed: " + err.message, true);
  } finally {
    e.target.value = "";
  }
});

// ---- settings + encryption flows ----
settingsBtn.addEventListener("click", () => {
  encUnencrypted.hidden = currentState.state !== "unencrypted";
  encUnlocked.hidden = currentState.state !== "unlocked";
  settingsDlg.showModal();
});
settingsClose.addEventListener("click", () => settingsDlg.close());

function openPassphrasePrompt({ title, requireConfirm = true, warning = true }) {
  return new Promise((resolve) => {
    passTitle.textContent = title;
    passConfirmRow.hidden = !requireConfirm;
    passConfirmRow.querySelector("input").required = requireConfirm;
    passWarn.hidden = !warning;
    passErr.textContent = "";
    passForm.reset();

    function cleanup() {
      passForm.removeEventListener("submit", onSubmit);
      passCancelBtn.removeEventListener("click", onCancel);
    }
    function onSubmit(e) {
      e.preventDefault();
      const p = passForm.elements.passphrase.value;
      if (requireConfirm) {
        const c = passForm.elements.confirm.value;
        if (p !== c) {
          passErr.textContent = "passphrases do not match";
          return;
        }
      }
      cleanup();
      passDlg.close();
      resolve(p);
    }
    function onCancel() {
      cleanup();
      passDlg.close();
      resolve(null);
    }
    passForm.addEventListener("submit", onSubmit);
    passCancelBtn.addEventListener("click", onCancel);
    passDlg.showModal();
  });
}

async function encryptCurrentData(passphrase) {
  const salt = randomSalt();
  const key = await deriveKey(passphrase, salt, KDF_ITERATIONS);
  const blob = await encryptObject(key, {
    tokens: currentState.tokens,
    certs: currentState.certs || [],
  });
  const vault = {
    version: VAULT_VERSION,
    salt: b64enc(salt),
    iterations: KDF_ITERATIONS,
    ...blob,
  };
  const jwk = await exportJWK(key);
  // Overwrite the plaintext slots with empty arrays before removing them, so the
  // most recent on-disk write for these keys is empty rather than the prior
  // plaintext (which would otherwise linger in chrome.storage.local's backing
  // log files until compaction).
  await chrome.storage.local.set({ vault, tokens: [], certs: [] });
  await chrome.storage.local.remove(["tokens", "certs"]);
  await chrome.storage.session.set({ key: jwk });
}

setupEncryptionBtn.addEventListener("click", async () => {
  settingsDlg.close();
  const pass = await openPassphrasePrompt({
    title: "set passphrase",
    requireConfirm: true,
  });
  if (!pass) return;
  try {
    await encryptCurrentData(pass);
    flash("vault encrypted");
  } catch (err) {
    flash("encryption failed: " + err.message, true);
  }
});

changePassBtn.addEventListener("click", async () => {
  settingsDlg.close();
  const pass = await openPassphrasePrompt({
    title: "new passphrase",
    requireConfirm: true,
  });
  if (!pass) return;
  try {
    await encryptCurrentData(pass);
    flash("passphrase updated");
  } catch (err) {
    flash("change failed: " + err.message, true);
  }
});

disableEncryptionBtn.addEventListener("click", async () => {
  settingsDlg.close();
  if (!confirm("remove encryption? data will be stored in plaintext.")) return;
  try {
    await chrome.storage.local.set({
      tokens: currentState.tokens,
      certs: currentState.certs || [],
    });
    await chrome.storage.local.remove("vault");
    await chrome.storage.session.remove("key");
    flash("encryption removed");
  } catch (err) {
    flash("failed: " + err.message, true);
  }
});

// ---- live updates ----
chrome.storage.onChanged.addListener((changes, area) => {
  if ((area === "local" && (changes.tokens || changes.certs || changes.vault)) ||
      (area === "session" && changes.key)) {
    refresh();
  }
});

// ===== JWT TOOLS =====================================================

const toolsBtn = $("#tools-btn");
const toolsDlg = $("#tools-dlg");
const toolsClose = $("#tools-close");

const decInput = $("#dec-input");
const decOutput = $("#dec-output");
const decHeader = $("#dec-header");
const decPayload = $("#dec-payload");
const decSig = $("#dec-sig");
const decClaims = $("#dec-claims");
const decClaimsBlock = $("#dec-claims-block");
const decErr = $("#dec-err");

const encAlg = $("#enc-alg");
const encHeader = $("#enc-header");
const encPayload = $("#enc-payload");
const encSecret = $("#enc-secret");
const encSecretLabel = $("#enc-secret-label");
const encBtn = $("#enc-btn");
const encOutput = $("#enc-output");
const encOutRow = $("#enc-out-row");
const encCopy = $("#enc-copy");
const encErr = $("#enc-err");

toolsBtn.addEventListener("click", () => {
  toolsDlg.showModal();
  if (!encHeader.value) {
    encHeader.value = JSON.stringify({ alg: "HS256", typ: "JWT" }, null, 2);
    encPayload.value = JSON.stringify({
      sub: "1234567890",
      name: "test",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    }, null, 2);
  }
});
toolsClose.addEventListener("click", () => toolsDlg.close());

// tabs
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((x) => x.classList.remove("active"));
    tab.classList.add("active");
    document.querySelector(`.tab-pane[data-pane="${tab.dataset.tab}"]`).classList.add("active");
  });
});

// --- decode ----------------------------------------------------------

function fmtTime(unixSec) {
  const d = new Date(unixSec * 1000);
  return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}
function relativeTime(unixSec) {
  const ms = unixSec * 1000 - Date.now();
  const abs = Math.abs(ms);
  const d = Math.floor(abs / 86400000);
  const h = Math.floor((abs / 3600000) % 24);
  const m = Math.floor((abs / 60000) % 60);
  const s = Math.floor((abs / 1000) % 60);
  let str;
  if (d > 0) str = `${d}d ${h}h`;
  else if (h > 0) str = `${h}h ${m}m`;
  else if (m > 0) str = `${m}m ${s}s`;
  else str = `${s}s`;
  return ms < 0 ? `${str} ago` : `in ${str}`;
}
function claimStatus(unixSec, kind) {
  const ms = unixSec * 1000 - Date.now();
  if (kind === "exp") {
    if (ms <= 0) return "expired";
    if (ms < 5 * 60 * 1000) return "urgent";
    if (ms < 60 * 60 * 1000) return "warn";
  }
  if (kind === "nbf" && ms > 0) return "warn"; // not yet valid
  return "";
}

// Populate a <ul> with the well-known JWT claims from `decoded`, formatting
// time-based claims (iat/nbf/exp/auth_time) as readable timestamps and showing
// iss/aud/sub as plain text. Returns true if any claim was added.
function populateClaimList(listEl, decoded) {
  listEl.replaceChildren();
  if (!decoded) return false;
  let any = false;
  const append = (label, value, statusCls = "") => {
    any = true;
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "claim-name";
    name.textContent = label;
    const val = document.createElement("span");
    val.className = "claim-value" + (statusCls ? " " + statusCls : "");
    val.textContent = value;
    li.append(name, val);
    listEl.append(li);
  };
  const timeClaims = [
    ["iat", "issued at"],
    ["nbf", "not before"],
    ["exp", "expires"],
    ["auth_time", "auth time"],
  ];
  for (const [k, label] of timeClaims) {
    const v = decoded.payload?.[k];
    if (typeof v !== "number") continue;
    append(label, `${fmtTime(v)} (${relativeTime(v)})`, claimStatus(v, k));
  }
  for (const [k, label] of [["iss", "issuer"], ["aud", "audience"], ["sub", "subject"]]) {
    const v = decoded.payload?.[k];
    if (v == null) continue;
    append(label, Array.isArray(v) ? v.join(", ") : String(v));
  }
  return any;
}

function decodeAndRender() {
  const raw = decInput.value.trim();
  decErr.textContent = "";
  decOutput.hidden = true;
  document.getElementById("verify-result").textContent = "";
  document.getElementById("verify-result").className = "verify-result";
  if (!raw) return;

  const parts = raw.split(".");
  if (parts.length < 2 || parts.length > 3) {
    decErr.textContent = "not a jwt (expected 2 or 3 segments)";
    return;
  }
  const decoded = decodeJwt(raw);
  if (!decoded) {
    decErr.textContent = "could not decode (invalid base64 or json)";
    return;
  }

  decHeader.textContent = JSON.stringify(decoded.header, null, 2);
  decPayload.textContent = JSON.stringify(decoded.payload, null, 2);
  decSig.textContent = parts[2] || "(unsigned)";
  document.getElementById("dec-verify-alg").textContent = decoded.header?.alg || "—";

  decClaimsBlock.hidden = !populateClaimList(decClaims, decoded);

  decOutput.hidden = false;
}

decInput.addEventListener("input", decodeAndRender);

// --- encode ----------------------------------------------------------

function bytesToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function jsonToB64url(obj) {
  return bytesToB64url(new TextEncoder().encode(JSON.stringify(obj)));
}
function importPemPkcs8(pem, algorithm) {
  const body = pem.trim()
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  if (!body) throw new Error("empty pem");
  const bin = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", bin.buffer, algorithm, false, ["sign"]);
}

async function signJwt(alg, header, payload, secret) {
  if (header.alg !== alg) header.alg = alg;
  const headerB64 = jsonToB64url(header);
  const payloadB64 = jsonToB64url(payload);
  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  let sig;
  if (alg === "HS256") {
    if (!secret) throw new Error("secret required for HS256");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    sig = await crypto.subtle.sign("HMAC", key, data);
  } else if (alg === "RS256") {
    const key = await importPemPkcs8(secret, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" });
    sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
  } else if (alg === "ES256") {
    const key = await importPemPkcs8(secret, { name: "ECDSA", namedCurve: "P-256" });
    sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data);
  } else {
    throw new Error("unsupported alg");
  }
  return `${headerB64}.${payloadB64}.${bytesToB64url(sig)}`;
}

encAlg.addEventListener("change", () => {
  // sync header alg
  try {
    const h = JSON.parse(encHeader.value);
    h.alg = encAlg.value;
    encHeader.value = JSON.stringify(h, null, 2);
  } catch {
    encHeader.value = JSON.stringify({ alg: encAlg.value, typ: "JWT" }, null, 2);
  }
  // hint
  if (encAlg.value === "HS256") {
    encSecretLabel.textContent = "secret";
    encSecret.placeholder = "your-256-bit-secret";
  } else {
    encSecretLabel.textContent = "private key (PEM, PKCS8)";
    encSecret.placeholder = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";
  }
});

encBtn.addEventListener("click", async () => {
  encErr.textContent = "";
  encOutRow.hidden = true;
  try {
    const header = JSON.parse(encHeader.value);
    const payload = JSON.parse(encPayload.value);
    const token = await signJwt(encAlg.value, header, payload, encSecret.value);
    encOutput.value = token;
    encOutRow.hidden = false;
  } catch (err) {
    encErr.textContent = err.message || String(err);
  }
});

encCopy.addEventListener("click", async () => {
  if (!encOutput.value) return;
  await navigator.clipboard.writeText(encOutput.value);
  flash("token copied");
});

// --- verify ----------------------------------------------------------

const verifyKey = $("#verify-key");
const verifyCert = $("#verify-cert");
const verifyBtn = $("#verify-btn");
const verifyResult = $("#verify-result");

function populateVerifyCertSelect() {
  const certs = currentState.certs || [];
  verifyCert.innerHTML = '<option value="">—</option>';
  for (const c of certs) {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = c.name + (c.env ? ` [${c.env}]` : "");
    verifyCert.append(opt);
  }
}

verifyCert.addEventListener("change", () => {
  if (!verifyCert.value) return;
  const cert = (currentState.certs || []).find((c) => c.id === verifyCert.value);
  if (cert) verifyKey.value = cert.pem;
});

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (s.length % 4)) % 4;
  const bin = atob(s + "=".repeat(pad));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifyJwt(jwt, keyText) {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("not a signed JWT");
  const decoded = decodeJwt(jwt);
  if (!decoded) throw new Error("could not decode JWT");
  const alg = decoded.header?.alg;
  if (!alg) throw new Error("no alg in header");

  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const sig = b64urlToBytes(parts[2]);
  if (!keyText.trim()) throw new Error("no key provided");

  if (alg === "HS256" || alg === "HS384" || alg === "HS512") {
    const hash = `SHA-${alg.slice(2)}`;
    const k = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(keyText),
      { name: "HMAC", hash },
      false,
      ["verify"]
    );
    return crypto.subtle.verify("HMAC", k, sig, data);
  }

  // RS256/384/512 or ES256/384/512: need SPKI bytes
  let spki;
  if (/-----BEGIN [A-Z0-9 ]*CERTIFICATE-----/i.test(keyText)) {
    spki = await spkiFromCertPem(keyText);
  } else if (/-----BEGIN [A-Z0-9 ]*PUBLIC KEY-----/i.test(keyText)) {
    spki = spkiFromPublicKeyPem(keyText);
  } else {
    throw new Error("expected PEM CERTIFICATE or PUBLIC KEY");
  }

  if (alg === "RS256" || alg === "RS384" || alg === "RS512") {
    const hash = `SHA-${alg.slice(2)}`;
    const k = await crypto.subtle.importKey(
      "spki",
      spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength),
      { name: "RSASSA-PKCS1-v1_5", hash },
      false,
      ["verify"]
    );
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", k, sig, data);
  }

  if (alg === "ES256" || alg === "ES384" || alg === "ES512") {
    const curve = { ES256: "P-256", ES384: "P-384", ES512: "P-521" }[alg];
    const hash = { ES256: "SHA-256", ES384: "SHA-384", ES512: "SHA-512" }[alg];
    const k = await crypto.subtle.importKey(
      "spki",
      spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength),
      { name: "ECDSA", namedCurve: curve },
      false,
      ["verify"]
    );
    return crypto.subtle.verify({ name: "ECDSA", hash }, k, sig, data);
  }

  throw new Error(`unsupported algorithm: ${alg}`);
}

verifyBtn.addEventListener("click", async () => {
  verifyResult.textContent = "verifying...";
  verifyResult.className = "verify-result";
  try {
    const ok = await verifyJwt(decInput.value.trim(), verifyKey.value);
    if (ok) {
      verifyResult.textContent = "✓ valid signature";
      verifyResult.className = "verify-result ok";
    } else {
      verifyResult.textContent = "✗ invalid signature (key does not match)";
      verifyResult.className = "verify-result fail";
    }
  } catch (err) {
    verifyResult.textContent = "✗ " + (err.message || String(err));
    verifyResult.className = "verify-result fail";
  }
});

refresh();
