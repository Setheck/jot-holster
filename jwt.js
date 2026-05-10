// jwt.js — pure JWT decode/expiry helpers (no DOM, no chrome APIs)

export function decodeJwt(token) {
  if (!token) return null;
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    return { header: decodeSegment(parts[0]), payload: decodeSegment(parts[1]) };
  } catch {
    return null;
  }
}

function decodeSegment(seg) {
  const pad = seg + "=".repeat((4 - (seg.length % 4)) % 4);
  const b64 = pad.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return JSON.parse(new TextDecoder().decode(bytes));
}

export function tokenExpiryMs(t) {
  const fromJwt = decodeJwt(t.value)?.payload?.exp;
  if (fromJwt) return fromJwt * 1000;
  if (t.expiresAt) return t.expiresAt;
  return null;
}

// Returns { text, expired } describing time-to-expiry.
// `now` is injectable for tests; defaults to Date.now().
export function expInfo(t, now = Date.now()) {
  const exp = tokenExpiryMs(t);
  if (!exp) return { text: "", expired: false };
  const ms = exp - now;
  if (ms <= 0) return { text: " · expired", expired: true };
  const d = Math.floor(ms / 86400000);
  const h = Math.floor((ms / 3600000) % 24);
  const m = Math.floor((ms / 60000) % 60);
  if (d > 0) return { text: ` · ${d}d ${h}h left`, expired: false };
  if (h > 0) return { text: ` · ${h}h ${m}m left`, expired: false };
  return { text: ` · ${m}m left`, expired: false };
}

// Status bucket from a JWT or expiresAt timestamp.
export function statusClass(t, now = Date.now()) {
  const exp = tokenExpiryMs(t);
  if (!exp) return "unknown";
  const ms = exp - now;
  if (ms <= 0) return "expired";
  if (ms < 5 * 60 * 1000) return "urgent";
  if (ms < 60 * 60 * 1000) return "warn";
  return "healthy";
}
