// vault.js — shared crypto helpers + storage state (ES module)

export const VAULT_VERSION = 1;
export const KDF_ITERATIONS = 600000;

const KDF_HASH = "SHA-256";
const KEY_LENGTH = 256;
const ALG = "AES-GCM";
const IV_BYTES = 12;
const SALT_BYTES = 16;

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64enc(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
export function b64dec(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
}

export async function deriveKey(passphrase, saltBytes, iterations = KDF_ITERATIONS) {
  const base = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: KDF_HASH },
    base, { name: ALG, length: KEY_LENGTH }, true, ["encrypt", "decrypt"]
  );
}

export async function encryptObject(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = await crypto.subtle.encrypt(
    { name: ALG, iv }, key, enc.encode(JSON.stringify(obj))
  );
  return { iv: b64enc(iv), ciphertext: b64enc(ct) };
}

export async function decryptObject(key, blob) {
  const ct = b64dec(blob.ciphertext);
  const iv = b64dec(blob.iv);
  const pt = await crypto.subtle.decrypt({ name: ALG, iv }, key, ct);
  return JSON.parse(dec.decode(pt));
}

export async function exportJWK(key) { return crypto.subtle.exportKey("jwk", key); }
export async function importJWK(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: ALG }, true, ["encrypt", "decrypt"]);
}

// State:
//   { state: "unencrypted", tokens, certs }
//   { state: "locked" }
//   { state: "unlocked",   tokens, certs }
export async function readVault() {
  const [{ tokens = [], certs = [], vault }, { key: jwk }] = await Promise.all([
    chrome.storage.local.get(["tokens", "certs", "vault"]),
    chrome.storage.session.get("key"),
  ]);
  if (!vault) return { state: "unencrypted", tokens, certs };
  if (!jwk) return { state: "locked" };
  try {
    const key = await importJWK(jwk);
    const data = await decryptObject(key, vault);
    return {
      state: "unlocked",
      tokens: data.tokens || [],
      certs: data.certs || [],
    };
  } catch {
    await chrome.storage.session.remove("key");
    return { state: "locked" };
  }
}

async function writeAll(tokens, certs) {
  const { vault } = await chrome.storage.local.get("vault");
  if (!vault) {
    await chrome.storage.local.set({ tokens, certs });
    return;
  }
  const { key: jwk } = await chrome.storage.session.get("key");
  if (!jwk) throw new Error("vault is locked");
  const key = await importJWK(jwk);
  const blob = await encryptObject(key, { tokens, certs });
  await chrome.storage.local.set({
    vault: {
      version: VAULT_VERSION,
      salt: vault.salt,
      iterations: vault.iterations,
      ...blob,
    },
  });
}

export async function writeTokens(tokens) {
  const cur = await readVault();
  const certs = cur.state === "locked" ? [] : (cur.certs || []);
  await writeAll(tokens, certs);
}

export async function writeCerts(certs) {
  const cur = await readVault();
  const tokens = cur.state === "locked" ? [] : (cur.tokens || []);
  await writeAll(tokens, certs);
}
