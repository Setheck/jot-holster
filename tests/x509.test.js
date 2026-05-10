import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCertificate, spkiFromCertPem, spkiFromPublicKeyPem } from "../x509.js";

// Self-signed RSA test cert generated with:
//   openssl req -x509 -newkey rsa:2048 -days 36500 -nodes
//     -subj "/CN=token-manager-test/O=Carbon Robotics/C=US"
//     -addext "subjectAltName=DNS:test.example.com,DNS:alt.example.com,IP:127.0.0.1"
//
// Cryptographically meaningless — exists only to exercise the X.509 parser.
const TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIUQQREI3Q0iPYXUTG7PcanWIQwNj8wDQYJKoZIhvcNAQEL
BQAwRDEbMBkGA1UEAwwSdG9rZW4tbWFuYWdlci10ZXN0MRgwFgYDVQQKDA9DYXJi
b24gUm9ib3RpY3MxCzAJBgNVBAYTAlVTMCAXDTI2MDUxMDAyMDMxMloYDzIxMjYw
NDE2MDIwMzEyWjBEMRswGQYDVQQDDBJ0b2tlbi1tYW5hZ2VyLXRlc3QxGDAWBgNV
BAoMD0NhcmJvbiBSb2JvdGljczELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDYr7VC+MyNLVKxDptWcWM1QZ1yh9lIH9N62TgYDRR/
NYymtCmuwsLZgUm5Lb3Y98JbnctslqynPuQx2el8rWiUPTlQbnh4dn/zSmaE2kuM
xxVLqryKOc9e9JsoNTMPJdl82c7ss9FPAVkZ8iRqBQMvJxUQQxEephgpw9h/uazI
Zut3GK6NocTQoQh86H3+y+oEt4p2fKrQX7oyzQ+JJIJwxBKtRi1Ds+r9NLpBJFIY
3rvheNR3BbpgTvwl5TesvaANGnjmi9r0BsM5bZk+Z0wtGEDhkM/vixDzgI11RNxj
15XpS6IIY+zK5hhyb4a5nUjdxLK9EpFJsm3dXwcGsF6JAgMBAAGjgYgwgYUwHQYD
VR0OBBYEFElN8mHdmRt6q15GAbJqweWqDLz8MB8GA1UdIwQYMBaAFElN8mHdmRt6
q15GAbJqweWqDLz8MA8GA1UdEwEB/wQFMAMBAf8wMgYDVR0RBCswKYIQdGVzdC5l
eGFtcGxlLmNvbYIPYWx0LmV4YW1wbGUuY29thwR/AAABMA0GCSqGSIb3DQEBCwUA
A4IBAQDODjqi6DIvTyUMU1nT1zEVuIzc48l7OgHnMbCyEnSwVSN4mPKc10zZVoH3
XbN6PoSm0E9NVOTQrxvw8HegUMzKD5QyveS2TeaffJK58d1mll698EBC4fqh5cBV
JswH57PM7c2Mbf527FZzTtQ8E79luM0RdMGNGn3WNAS+DXje5c/3R9+XUUb/IrUY
PDql1b+Wi2bZttGNMlpG4jyt9KY15BWiuShrqGt0XtCEGgYNhJtTiCUUAxXMsznp
5cu8UdJfI6sJkLB56/3bBdtW4S6LISrCadnlLsJn1qZb5MamuWmrK8WjXwTSS3+r
Mob7HDEbXw8jzCgTAliwISKcCjUG
-----END CERTIFICATE-----`;

const EXPECTED_FINGERPRINT_NORMALIZED =
  "39:04:24:36:94:09:BB:B6:63:9B:51:E3:83:BB:5B:4C:FD:58:E2:36:3D:98:D1:FE:CF:25:0F:FF:6C:4E:64:FC";

test("parseCertificate extracts subject and issuer RDNs", async () => {
  const c = await parseCertificate(TEST_CERT_PEM);
  // RDN-string ordering depends on what's in the cert; we just check parts are present.
  assert.match(c.subject, /CN=token-manager-test/);
  assert.match(c.subject, /O=Carbon Robotics/);
  assert.match(c.subject, /C=US/);
  // self-signed → issuer == subject
  assert.equal(c.issuer, c.subject);

  const cn = c.subjectRdns.find((r) => r.name === "CN");
  assert.equal(cn.value, "token-manager-test");
});

test("parseCertificate extracts validity dates", async () => {
  const c = await parseCertificate(TEST_CERT_PEM);
  // Valid ISO 8601 strings
  assert.match(c.notBefore, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(c.notAfter, /^\d{4}-\d{2}-\d{2}T/);
  // notAfter > notBefore
  assert.ok(Date.parse(c.notAfter) > Date.parse(c.notBefore));
});

test("parseCertificate extracts SHA-256 fingerprint matching openssl", async () => {
  const c = await parseCertificate(TEST_CERT_PEM);
  assert.equal(c.fingerprint.toUpperCase(), EXPECTED_FINGERPRINT_NORMALIZED);
});

test("parseCertificate extracts SubjectAltName entries", async () => {
  const c = await parseCertificate(TEST_CERT_PEM);
  assert.deepEqual(c.sans.dnsNames.sort(), ["alt.example.com", "test.example.com"]);
  assert.deepEqual(c.sans.ipAddresses, ["127.0.0.1"]);
});

test("parseCertificate identifies the public key algorithm", async () => {
  const c = await parseCertificate(TEST_CERT_PEM);
  assert.equal(c.publicKeyAlgorithm, "rsaEncryption");
  assert.equal(c.publicKeyOid, "1.2.840.113549.1.1.1");
});

test("parseCertificate exposes SPKI bytes that crypto.subtle accepts", async () => {
  const c = await parseCertificate(TEST_CERT_PEM);
  const spki = Uint8Array.from(atob(c.spkiBase64), (ch) => ch.charCodeAt(0));
  // Web Crypto should be able to import this SPKI as an RSA public key.
  const key = await crypto.subtle.importKey(
    "spki",
    spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  assert.equal(key.type, "public");
  assert.equal(key.algorithm.name, "RSASSA-PKCS1-v1_5");
});

test("parseCertificate rejects non-CERTIFICATE PEMs", async () => {
  const fakePubKey = `-----BEGIN PUBLIC KEY-----\nMIIBIj==\n-----END PUBLIC KEY-----`;
  await assert.rejects(() => parseCertificate(fakePubKey), /expected CERTIFICATE/);
});

test("spkiFromCertPem returns the same SPKI bytes as parseCertificate", async () => {
  const spki = await spkiFromCertPem(TEST_CERT_PEM);
  const c = await parseCertificate(TEST_CERT_PEM);
  const expected = Uint8Array.from(atob(c.spkiBase64), (ch) => ch.charCodeAt(0));
  assert.deepEqual(Array.from(spki), Array.from(expected));
});

test("spkiFromPublicKeyPem rejects a CERTIFICATE PEM", () => {
  assert.throws(() => spkiFromPublicKeyPem(TEST_CERT_PEM), /expected PUBLIC KEY/);
});
