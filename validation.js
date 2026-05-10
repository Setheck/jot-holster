// validation.js — small pure validators used by the editor (no DOM, no chrome APIs).

// Returns true when the host portion of a `declarativeNetRequest`-style URL
// pattern is `*` (or empty), meaning the Authorization header would be injected
// on every host the user visits.
export function isBroadPattern(p) {
  if (!p) return false;
  const trimmed = p.trim();
  if (!trimmed || trimmed === "*" || trimmed === "*/*") return true;
  const noScheme = trimmed.replace(/^[a-z]+:\/\//i, "");
  const host = noScheme.split("/")[0];
  return host === "" || host === "*" || host === "*.";
}

// Returns true when the URL uses the http:// scheme (i.e. cleartext).
export function isInsecureUrl(url) {
  return /^\s*http:\/\//i.test(url || "");
}

// RFC 7230 §3.2.6 token characters. Header field-name must match this — the
// declarativeNetRequest API will silently reject rules whose header names don't.
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9a-zA-Z]+$/;
export function isValidHeaderName(name) {
  if (!name) return false;
  return HEADER_NAME_RE.test(name);
}
