import { test } from "node:test";
import assert from "node:assert/strict";
import { isBroadPattern, isInsecureUrl } from "../validation.js";

test("isBroadPattern flags wildcards covering every host", () => {
  for (const p of [
    "*",
    "*/*",
    "https://*/*",
    "http://*/*",
    "https://*",
    "http://*",
    "https://*.",
    "  https://*/*  ",
  ]) {
    assert.equal(isBroadPattern(p), true, `expected broad: ${JSON.stringify(p)}`);
  }
});

test("isBroadPattern leaves narrow patterns alone", () => {
  for (const p of [
    "https://api.example.com/*",
    "https://*.example.com/*", // subdomain wildcard, host portion is "*.example.com"
    "https://example.com",
    "https://example.com/v1/*",
    "http://localhost:8080/*",
  ]) {
    assert.equal(isBroadPattern(p), false, `expected narrow: ${JSON.stringify(p)}`);
  }
});

test("isBroadPattern handles empty / nullish inputs", () => {
  assert.equal(isBroadPattern(""), false);
  assert.equal(isBroadPattern(null), false);
  assert.equal(isBroadPattern(undefined), false);
});

test("isInsecureUrl flags http only, not https", () => {
  assert.equal(isInsecureUrl("http://idp.example.com/oauth/token"), true);
  assert.equal(isInsecureUrl("HTTP://IDP.EXAMPLE.COM"), true);
  assert.equal(isInsecureUrl("  http://localhost"), true);
  assert.equal(isInsecureUrl("https://idp.example.com/oauth/token"), false);
  assert.equal(isInsecureUrl("HTTPS://idp.example.com"), false);
});

test("isInsecureUrl handles empty / nullish inputs", () => {
  assert.equal(isInsecureUrl(""), false);
  assert.equal(isInsecureUrl(null), false);
  assert.equal(isInsecureUrl(undefined), false);
});

test("isInsecureUrl does not flag URLs that merely contain 'http' in the path", () => {
  assert.equal(isInsecureUrl("https://example.com/redirect?to=http://other"), false);
});
