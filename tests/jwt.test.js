import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeJwt, expInfo, statusClass } from "../jwt.js";

// A real-looking JWT (HS256) signed with secret "test". Payload exp far in the future.
// Header:  {"alg":"HS256","typ":"JWT"}
// Payload: {"sub":"42","name":"alice","iat":1700000000,"exp":4102444800}
const FUTURE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiI0MiIsIm5hbWUiOiJhbGljZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwfQ." +
  "x";

// {"alg":"HS256","typ":"JWT"} . {"sub":"old","exp":1000000} . sig
const PAST_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiJvbGQiLCJleHAiOjEwMDAwMDB9." +
  "x";

// Header only — payload uses url-safe chars and no padding requirement
// {"sub":"汉字","exp":4102444800}  — utf-8 multi-byte
const UNICODE_PAYLOAD = Buffer.from(
  JSON.stringify({ sub: "汉字", exp: 4102444800 }),
  "utf8",
).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const UNICODE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + UNICODE_PAYLOAD + ".x";

test("decodeJwt parses header and payload", () => {
  const out = decodeJwt(FUTURE_JWT);
  assert.deepEqual(out.header, { alg: "HS256", typ: "JWT" });
  assert.equal(out.payload.sub, "42");
  assert.equal(out.payload.name, "alice");
  assert.equal(out.payload.exp, 4102444800);
});

test("decodeJwt handles utf-8 multi-byte payloads", () => {
  const out = decodeJwt(UNICODE_JWT);
  assert.equal(out.payload.sub, "汉字");
});

test("decodeJwt returns null for empty/invalid input", () => {
  assert.equal(decodeJwt(""), null);
  assert.equal(decodeJwt(null), null);
  assert.equal(decodeJwt(undefined), null);
  assert.equal(decodeJwt("not-a-jwt"), null);
  assert.equal(decodeJwt("only.one"), null); // wait, two parts is OK
});

test("decodeJwt accepts a 2-segment (unsigned) token", () => {
  // header.payload with no signature
  const twoPart =
    "eyJhbGciOiJub25lIn0." +
    "eyJzdWIiOiJ4In0";
  const out = decodeJwt(twoPart);
  assert.equal(out.header.alg, "none");
  assert.equal(out.payload.sub, "x");
});

test("decodeJwt returns null when a segment is not valid base64-url JSON", () => {
  assert.equal(decodeJwt("notbase64.notbase64.x"), null);
  // Valid base64 but not JSON
  const garbage = Buffer.from("not json").toString("base64url");
  assert.equal(decodeJwt(`${garbage}.${garbage}.x`), null);
});

test("expInfo returns expired for past exp", () => {
  const now = 4102444800 * 1000 + 1; // 1ms after PAST_JWT exp would still be in past
  const r = expInfo({ value: PAST_JWT }, now);
  assert.equal(r.expired, true);
  assert.equal(r.text, " · expired");
});

test("expInfo returns days/hours for future exp", () => {
  // 2d 3h 4m before exp
  const exp = 4102444800;
  const now = exp * 1000 - (2 * 86400000 + 3 * 3600000 + 4 * 60000);
  const r = expInfo({ value: FUTURE_JWT }, now);
  assert.equal(r.expired, false);
  assert.equal(r.text, " · 2d 3h left");
});

test("expInfo returns hours/minutes when under a day", () => {
  const exp = 4102444800;
  const now = exp * 1000 - (3 * 3600000 + 15 * 60000);
  const r = expInfo({ value: FUTURE_JWT }, now);
  assert.equal(r.text, " · 3h 15m left");
});

test("expInfo returns minutes-only when under an hour", () => {
  const exp = 4102444800;
  const now = exp * 1000 - 27 * 60000;
  const r = expInfo({ value: FUTURE_JWT }, now);
  assert.equal(r.text, " · 27m left");
});

test("expInfo falls back to t.expiresAt when JWT has no exp", () => {
  const t = { value: "not.a.jwt", expiresAt: Date.now() + 5 * 60000 };
  const r = expInfo(t);
  assert.equal(r.expired, false);
});

test("expInfo returns empty when no expiry info available", () => {
  assert.deepEqual(expInfo({ value: "" }), { text: "", expired: false });
  assert.deepEqual(expInfo({ value: "not.a.jwt" }), { text: "", expired: false });
});

test("statusClass buckets correctly", () => {
  const exp = 4102444800;
  const t = { value: FUTURE_JWT };

  // healthy: > 1h
  assert.equal(statusClass(t, exp * 1000 - 2 * 3600000), "healthy");
  // warn: < 1h, > 5min
  assert.equal(statusClass(t, exp * 1000 - 30 * 60000), "warn");
  // urgent: < 5min
  assert.equal(statusClass(t, exp * 1000 - 60000), "urgent");
  // expired
  assert.equal(statusClass(t, exp * 1000 + 1), "expired");
  // unknown when no expiry info
  assert.equal(statusClass({ value: "not.a.jwt" }), "unknown");
});
