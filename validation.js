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
