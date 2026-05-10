// x509.js — minimal X.509 + ASN.1 DER parser
//
// Supports extracting the common cert fields for display:
//   subject, issuer (RDN strings)
//   notBefore, notAfter (Date objects)
//   serialNumber (hex)
//   publicKeyAlgorithm (oid name)
//   spki (Uint8Array, full DER of SubjectPublicKeyInfo, ready for crypto.subtle.importKey("spki", ...))
//   sans (string[] of dNSName entries)
//   fingerprint (sha-256 hex of full DER, colon-separated)
//
// This is not a full X.509 implementation — extension parsing is limited to SAN.

const OIDS = {
  // RDN attributes
  "2.5.4.3": "CN",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "STREET",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "1.2.840.113549.1.9.1": "emailAddress",
  // public key algos
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.10045.2.1": "ecPublicKey",
  "1.3.101.112": "Ed25519",
  // ec curves
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
  // signature algos (for display only)
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
  "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
  // extension oids
  "2.5.29.17": "subjectAltName",
  "2.5.29.15": "keyUsage",
  "2.5.29.37": "extKeyUsage",
};

class R {
  constructor(buf, start = 0, end = buf.length) {
    this.buf = buf;
    this.pos = start;
    this.end = end;
  }
  done() { return this.pos >= this.end; }
  next() {
    const tagStart = this.pos;
    const tag = this.buf[this.pos++];
    let length = this.buf[this.pos++];
    if (length & 0x80) {
      const n = length & 0x7f;
      length = 0;
      for (let i = 0; i < n; i++) length = (length << 8) | this.buf[this.pos++];
    }
    const valueStart = this.pos;
    const valueEnd = valueStart + length;
    return { tag, tagStart, valueStart, valueEnd, length };
  }
  enter(n) { return new R(this.buf, n.valueStart, n.valueEnd); }
  bytes(n) { return this.buf.subarray(n.valueStart, n.valueEnd); }
  skip(n) { this.pos = n.valueEnd; }
}

function readOID(bytes) {
  if (!bytes.length) return "";
  const out = [];
  out.push(Math.floor(bytes[0] / 40));
  out.push(bytes[0] % 40);
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      out.push(value);
      value = 0;
    }
  }
  return out.join(".");
}

function readUTCTime(bytes) {
  const s = String.fromCharCode(...bytes);
  let yy = parseInt(s.slice(0, 2), 10);
  yy = yy < 50 ? 2000 + yy : 1900 + yy;
  return new Date(Date.UTC(
    yy,
    parseInt(s.slice(2, 4), 10) - 1,
    parseInt(s.slice(4, 6), 10),
    parseInt(s.slice(6, 8), 10),
    parseInt(s.slice(8, 10), 10),
    s.length >= 13 ? parseInt(s.slice(10, 12), 10) : 0
  ));
}

function readGeneralizedTime(bytes) {
  const s = String.fromCharCode(...bytes);
  return new Date(Date.UTC(
    parseInt(s.slice(0, 4), 10),
    parseInt(s.slice(4, 6), 10) - 1,
    parseInt(s.slice(6, 8), 10),
    parseInt(s.slice(8, 10), 10),
    parseInt(s.slice(10, 12), 10),
    s.length >= 14 ? parseInt(s.slice(12, 14), 10) : 0
  ));
}

function readTime(node, r) {
  return node.tag === 0x17 ? readUTCTime(r.bytes(node)) : readGeneralizedTime(r.bytes(node));
}

function decodeStr(bytes) {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function parseName(bytes) {
  const r = new R(bytes);
  const out = [];
  while (!r.done()) {
    const rdn = r.next(); // SET
    const setR = r.enter(rdn);
    while (!setR.done()) {
      const atv = setR.next(); // SEQUENCE
      const atvR = setR.enter(atv);
      const oidNode = atvR.next();
      const oidStr = readOID(atvR.bytes(oidNode));
      atvR.skip(oidNode);
      const valNode = atvR.next();
      const value = decodeStr(atvR.bytes(valNode));
      out.push({ oid: oidStr, name: OIDS[oidStr] || oidStr, value });
      setR.skip(atv);
    }
    r.skip(rdn);
  }
  return out;
}

function rdnString(rdns) {
  return rdns.map((r) => `${r.name}=${r.value}`).join(", ");
}

function parseSAN(octetStringBytes) {
  // The OCTET STRING wraps a SEQUENCE of GeneralName
  const r = new R(octetStringBytes);
  const seq = r.next();
  if (seq.tag !== 0x30) return [];
  const gnR = r.enter(seq);
  const dnsNames = [];
  const ipAddresses = [];
  const uris = [];
  const emails = [];
  while (!gnR.done()) {
    const gn = gnR.next();
    // tag is context-specific [n] IMPLICIT
    // [1] rfc822Name (email), [2] dNSName, [6] uniformResourceIdentifier, [7] iPAddress
    if (gn.tag === 0x82) dnsNames.push(decodeStr(gnR.bytes(gn)));
    else if (gn.tag === 0x81) emails.push(decodeStr(gnR.bytes(gn)));
    else if (gn.tag === 0x86) uris.push(decodeStr(gnR.bytes(gn)));
    else if (gn.tag === 0x87) {
      const b = gnR.bytes(gn);
      if (b.length === 4) ipAddresses.push([...b].join("."));
      else if (b.length === 16) {
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
          parts.push(((b[i] << 8) | b[i + 1]).toString(16));
        }
        ipAddresses.push(parts.join(":"));
      }
    }
    gnR.skip(gn);
  }
  return { dnsNames, ipAddresses, uris, emails };
}

function parseExtensions(extBytes) {
  // [3] EXPLICIT wraps Extensions ::= SEQUENCE OF Extension
  const r = new R(extBytes);
  const seq = r.next();
  if (seq.tag !== 0x30) return {};
  const extR = r.enter(seq);
  const result = { sans: { dnsNames: [], ipAddresses: [], uris: [], emails: [] } };
  while (!extR.done()) {
    const ext = extR.next(); // Extension SEQUENCE
    const eR = extR.enter(ext);
    const oidNode = eR.next();
    const oid = readOID(eR.bytes(oidNode));
    eR.skip(oidNode);
    let next = eR.next();
    if (next.tag === 0x01) {
      // optional critical BOOLEAN
      eR.skip(next);
      next = eR.next();
    }
    // OCTET STRING
    const octetBytes = eR.bytes(next);
    if (oid === "2.5.29.17") {
      const sans = parseSAN(octetBytes);
      result.sans = sans;
    }
    extR.skip(ext);
  }
  return result;
}

function pemToDer(pem) {
  const m = pem.trim().match(/-----BEGIN ([A-Z ]+)-----([\s\S]+?)-----END \1-----/);
  if (!m) throw new Error("invalid PEM (no BEGIN/END markers)");
  const body = m[2].replace(/\s+/g, "");
  return { type: m[1], der: Uint8Array.from(atob(body), (c) => c.charCodeAt(0)) };
}

function bytesHex(bytes, sep = ":") {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(sep);
}

export async function parseCertificate(pem) {
  const { type, der } = pemToDer(pem);
  if (!type.includes("CERTIFICATE")) throw new Error(`expected CERTIFICATE, got ${type}`);

  const top = new R(der);
  const cert = top.next();
  if (cert.tag !== 0x30) throw new Error("not a SEQUENCE");

  const tbs = top.enter(cert).next();
  if (tbs.tag !== 0x30) throw new Error("tbs not SEQUENCE");
  const t = top.enter(cert).enter(tbs);

  // version (optional [0] EXPLICIT INTEGER)
  let cur = t.next();
  let version = 1;
  if (cur.tag === 0xa0) {
    const vR = t.enter(cur);
    const vn = vR.next();
    version = vR.bytes(vn)[0] + 1;
    t.skip(cur);
    cur = t.next();
  }
  // serialNumber INTEGER
  const serial = bytesHex(t.bytes(cur));
  t.skip(cur);

  // signature AlgorithmIdentifier (skip)
  const sigAlgNode = t.next();
  t.skip(sigAlgNode);

  // issuer Name
  const issuerNode = t.next();
  const issuer = parseName(t.bytes(issuerNode));
  t.skip(issuerNode);

  // validity SEQUENCE { notBefore, notAfter }
  const validityNode = t.next();
  const vR = t.enter(validityNode);
  const nb = vR.next();
  const notBefore = readTime(nb, vR);
  vR.skip(nb);
  const na = vR.next();
  const notAfter = readTime(na, vR);
  t.skip(validityNode);

  // subject Name
  const subjectNode = t.next();
  const subject = parseName(t.bytes(subjectNode));
  t.skip(subjectNode);

  // subjectPublicKeyInfo SEQUENCE
  const spkiNode = t.next();
  const spkiBytes = der.slice(spkiNode.tagStart, spkiNode.valueEnd);
  const sR = t.enter(spkiNode);
  const algNode = sR.next();
  const aR = sR.enter(algNode);
  const algOidNode = aR.next();
  const algOid = readOID(aR.bytes(algOidNode));
  let algName = OIDS[algOid] || algOid;
  // for EC, second item is the curve OID
  if (algOid === "1.2.840.10045.2.1") {
    aR.skip(algOidNode);
    if (!aR.done()) {
      const curveNode = aR.next();
      if (curveNode.tag === 0x06) {
        const curveOid = readOID(aR.bytes(curveNode));
        algName += ` (${OIDS[curveOid] || curveOid})`;
      }
    }
  }
  t.skip(spkiNode);

  // skip optional issuerUniqueID [1] / subjectUniqueID [2]
  let extensions = {};
  while (!t.done()) {
    const next = t.next();
    if (next.tag === 0xa3) {
      // extensions [3] EXPLICIT
      extensions = parseExtensions(t.bytes(next));
      t.skip(next);
      break;
    }
    t.skip(next);
  }

  const fpBuf = await crypto.subtle.digest("SHA-256", der);
  const fingerprint = bytesHex(new Uint8Array(fpBuf));

  return {
    version,
    serialNumber: serial,
    issuer: rdnString(issuer),
    issuerRdns: issuer,
    subject: rdnString(subject),
    subjectRdns: subject,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    publicKeyAlgorithm: algName,
    publicKeyOid: algOid,
    spkiBase64: btoa(String.fromCharCode(...spkiBytes)),
    sans: extensions.sans || { dnsNames: [], ipAddresses: [], uris: [], emails: [] },
    fingerprint,
  };
}

// Extract SPKI bytes from a cert PEM (for crypto.subtle.importKey "spki")
export async function spkiFromCertPem(pem) {
  const info = await parseCertificate(pem);
  return Uint8Array.from(atob(info.spkiBase64), (c) => c.charCodeAt(0));
}

// Extract SPKI bytes from a "PUBLIC KEY" PEM
export function spkiFromPublicKeyPem(pem) {
  const { type, der } = pemToDer(pem);
  if (!type.includes("PUBLIC KEY")) throw new Error(`expected PUBLIC KEY, got ${type}`);
  return der;
}
