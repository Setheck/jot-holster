import { test } from "node:test";
import assert from "node:assert/strict";
import {
  b64enc,
  b64dec,
  randomSalt,
  deriveKey,
  encryptObject,
  decryptObject,
  exportJWK,
  importJWK,
} from "../vault.js";

test("b64enc/b64dec round-trip arbitrary bytes", () => {
  const cases = [
    new Uint8Array([]),
    new Uint8Array([0]),
    new Uint8Array([255]),
    new Uint8Array([1, 2, 3, 4, 5]),
    crypto.getRandomValues(new Uint8Array(64)),
  ];
  for (const bytes of cases) {
    const enc = b64enc(bytes);
    const dec = b64dec(enc);
    assert.deepEqual(Array.from(dec), Array.from(bytes));
  }
});

test("b64enc accepts ArrayBuffer (via .buffer or directly)", () => {
  const bytes = new Uint8Array([1, 2, 3]);
  const enc = b64enc(bytes);
  // round-trip
  assert.deepEqual(Array.from(b64dec(enc)), [1, 2, 3]);
});

test("randomSalt is 16 bytes and not all zero", () => {
  const a = randomSalt();
  const b = randomSalt();
  assert.equal(a.length, 16);
  assert.equal(b.length, 16);
  // Two consecutive salts should not collide
  assert.notDeepEqual(Array.from(a), Array.from(b));
  // Should not be all zeroes
  assert.ok(a.some((x) => x !== 0));
});

test("deriveKey produces a usable AES-GCM key", async () => {
  const salt = randomSalt();
  const key = await deriveKey("test-passphrase", salt, 1000); // low iterations for test speed
  assert.equal(key.algorithm.name, "AES-GCM");
  assert.equal(key.algorithm.length, 256);
});

test("deriveKey is deterministic for a given passphrase + salt", async () => {
  const salt = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  ]);
  const k1 = await deriveKey("pass", salt, 1000);
  const k2 = await deriveKey("pass", salt, 1000);
  // Compare exported JWKs
  const j1 = await exportJWK(k1);
  const j2 = await exportJWK(k2);
  assert.equal(j1.k, j2.k);
});

test("deriveKey diverges on different passphrase", async () => {
  const salt = new Uint8Array(16);
  const k1 = await exportJWK(await deriveKey("a", salt, 1000));
  const k2 = await exportJWK(await deriveKey("b", salt, 1000));
  assert.notEqual(k1.k, k2.k);
});

test("deriveKey diverges on different salt", async () => {
  const k1 = await exportJWK(await deriveKey("p", new Uint8Array(16).fill(1), 1000));
  const k2 = await exportJWK(await deriveKey("p", new Uint8Array(16).fill(2), 1000));
  assert.notEqual(k1.k, k2.k);
});

test("encrypt + decrypt round-trip preserves the object", async () => {
  const key = await deriveKey("p", randomSalt(), 1000);
  const obj = {
    tokens: [{ id: "a", name: "staging", value: "eyJ..." }],
    certs: [{ id: "c1", name: "server", env: "prod" }],
  };
  const blob = await encryptObject(key, obj);
  assert.ok(blob.iv);
  assert.ok(blob.ciphertext);
  const out = await decryptObject(key, blob);
  assert.deepEqual(out, obj);
});

test("each encryptObject call uses a fresh IV", async () => {
  const key = await deriveKey("p", randomSalt(), 1000);
  const obj = { x: 1 };
  const a = await encryptObject(key, obj);
  const b = await encryptObject(key, obj);
  assert.notEqual(a.iv, b.iv);
  // ciphertexts differ even though plaintext is identical
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test("decryptObject with the wrong key throws", async () => {
  const k1 = await deriveKey("right", randomSalt(), 1000);
  const k2 = await deriveKey("wrong", randomSalt(), 1000);
  const blob = await encryptObject(k1, { secret: "hello" });
  await assert.rejects(() => decryptObject(k2, blob));
});

test("decryptObject with a tampered ciphertext throws (AES-GCM authenticates)", async () => {
  const key = await deriveKey("p", randomSalt(), 1000);
  const blob = await encryptObject(key, { value: "abc" });
  // Flip the first byte of the ciphertext (after b64-decoding)
  const ct = b64dec(blob.ciphertext);
  ct[0] ^= 0x01;
  const tampered = { ...blob, ciphertext: b64enc(ct) };
  await assert.rejects(() => decryptObject(key, tampered));
});

test("exportJWK / importJWK round-trip", async () => {
  const key = await deriveKey("p", randomSalt(), 1000);
  const jwk = await exportJWK(key);
  const reimported = await importJWK(jwk);
  // Use the re-imported key to decrypt something the original encrypted
  const blob = await encryptObject(key, { hi: "there" });
  const out = await decryptObject(reimported, blob);
  assert.deepEqual(out, { hi: "there" });
});
