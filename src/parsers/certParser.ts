import * as crypto from "crypto";
import * as forge from "node-forge";
import {
  CertificateInfo,
  CertificateSubject,
  SubjectAlternativeName,
  CertificateExtension,
  CertificateFinding,
} from "../models/certificate";
import { derToPem, splitPemBlocks } from "./pemParser";
import { assertWithinInputLimit, MAX_CERTIFICATES } from "./limits";

const EXTENDED_KEY_USAGE_OID: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
  "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
  "1.3.6.1.5.5.7.3.3": "Code Signing",
  "1.3.6.1.5.5.7.3.4": "Email Protection",
  "1.3.6.1.5.5.7.3.8": "Time Stamping",
  "1.3.6.1.5.5.7.3.9": "OCSP Signing",
};

const OID_NAMES: Record<string, string> = {
  "2.5.29.9": "Subject Directory Attributes",
  "2.5.29.14": "Subject Key Identifier",
  "2.5.29.15": "Key Usage",
  "2.5.29.17": "Subject Alternative Name",
  "2.5.29.18": "Issuer Alternative Name",
  "2.5.29.19": "Basic Constraints",
  "2.5.29.30": "Name Constraints",
  "2.5.29.31": "CRL Distribution Points",
  "2.5.29.32": "Certificate Policies",
  "2.5.29.35": "Authority Key Identifier",
  "2.5.29.37": "Extended Key Usage",
  "1.3.6.1.5.5.7.1.1": "Authority Information Access",
  "1.3.6.1.5.5.7.1.24": "TLS Feature",
};

const FORGE_EXTENSION_OIDS: Record<string, string> = {
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  subjectAltName: "2.5.29.17",
  issuerAltName: "2.5.29.18",
  basicConstraints: "2.5.29.19",
  cRLDistributionPoints: "2.5.29.31",
  certificatePolicies: "2.5.29.32",
  authorityKeyIdentifier: "2.5.29.35",
  extKeyUsage: "2.5.29.37",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
};

/**
 * Parses a PEM or DER certificate file.
 * Handles multi-cert PEM chains (returns one entry per cert).
 */
export function parseCertificateFile(content: string | Uint8Array): CertificateInfo[] {
  let pems: string[];

  if (typeof content === "string") {
    assertWithinInputLimit(Buffer.byteLength(content, "utf8"), "Certificate file");
    const blocks = splitPemBlocks(content).filter(b => b.type === "CERTIFICATE");
    if (blocks.length === 0) {
      throw new Error("No CERTIFICATE blocks found in the file.");
    }
    pems = blocks.map(b => b.pem);
  } else {
    assertWithinInputLimit(content.byteLength, "Certificate file");
    pems = [derToPem(content)];
  }

  if (pems.length > MAX_CERTIFICATES) {
    throw new Error(`Certificate file exceeds the maximum of ${MAX_CERTIFICATES} certificates.`);
  }

  return pems.map((pem, idx) => {
    try {
      return parseSinglePem(pem);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Certificate #${idx + 1}: ${msg}`);
    }
  });
}

function parseSinglePem(pem: string): CertificateInfo {
  const x509 = new crypto.X509Certificate(pem);
  const forgeCert = tryParseForgeCertificate(pem);

  const subject = forgeCert ? parseForgeName(forgeCert.subject.attributes, x509.subject) : parseX509Name(x509.subject);
  const issuer = forgeCert ? parseForgeName(forgeCert.issuer.attributes, x509.issuer) : parseX509Name(x509.issuer);

  // keyUsage is string[] in Node.js ≥15.6
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const x509any = x509 as any;
  const keyUsage = (forgeCert ? parseKeyUsage(forgeCert) : undefined) ?? normalizeKeyUsage(x509any.keyUsage);
  const extendedKeyUsage = forgeCert ? parseExtendedKeyUsage(forgeCert, x509any.extendedKeyUsage ?? []) : parseExtendedKeyUsage(undefined, x509any.extendedKeyUsage ?? []);
  const { algorithm, keySize } = getPublicKeyInfo(x509.publicKey);
  const extensions = buildExtensions(x509, forgeCert);
  const basicConstraints = forgeCert ? parseBasicConstraints(forgeCert) : undefined;
  const nameConstraints = forgeCert ? extensionValue(forgeCert, "2.5.29.30") : undefined;
  const findings = validateCertificate(x509, subject, keyUsage, extendedKeyUsage, extensions, basicConstraints);

  return {
    pem,
    version: 3,
    serialNumber: formatSerial(x509.serialNumber),
    subject,
    issuer,
    validity: {
      notBefore: new Date(x509.validFrom),
      notAfter: new Date(x509.validTo),
    },
    subjectAltNames: parseSubjectAltNames(x509.subjectAltName ?? ""),
    keyUsage,
    extendedKeyUsage,
    extensions,
    basicConstraints,
    nameConstraints,
    signatureAlgorithm: (x509 as { signatureAlgorithm?: string }).signatureAlgorithm ?? "Unknown",
    publicKeyAlgorithm: algorithm,
    publicKeySize: keySize,
    publicKeyPem: x509.publicKey.export({ type: "spki", format: "pem" }).toString(),
    fingerprints: {
      sha1: x509.fingerprint.toUpperCase(),
      sha256: x509.fingerprint256.toUpperCase(),
    },
    isSelfSigned: x509.subject === x509.issuer,
    isCA: basicConstraints?.ca ?? safeCA(x509),
    findings,
  };
}

function tryParseForgeCertificate(pem: string): forge.pki.Certificate | undefined {
  try {
    return forge.pki.certificateFromPem(pem);
  } catch {
    return undefined;
  }
}

// Node.js ≥18 returns string[], ≤17 returned a comma-separated string.
// Handle both to be safe.
function normalizeKeyUsage(raw: string[] | string | undefined): string[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  return raw.split(/,\s*/).map(s => s.trim()).filter(Boolean);
}

function parseExtendedKeyUsage(cert: forge.pki.Certificate | undefined, nodeEkus: string[]): string[] {
  const ext = cert?.extensions.find(e => (e as { id?: string }).id === "2.5.29.37" || e.name === "extKeyUsage") as Record<string, unknown> | undefined;
  if (ext) {
    const names = Object.entries(ext)
      .filter(([key, value]) => value === true && !["critical"].includes(key))
      .map(([key]) => key);
    if (names.length) return names;
  }
  return nodeEkus.map(oid => EXTENDED_KEY_USAGE_OID[oid] ?? OID_NAMES[oid] ?? oid);
}

export function parseX509Name(nameStr: string): CertificateSubject {
  const result: CertificateSubject = {};
  if (!nameStr) return result;

  const parts = splitX509Name(nameStr);

  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toUpperCase();
    const value = unescapeX509Value(part.slice(eq + 1).trim());

    switch (key) {
      case "CN":            result.commonName = value; break;
      case "O":             (result.organization ??= []).push(value); break;
      case "OU":            (result.organizationalUnit ??= []).push(value); break;
      case "C":             (result.country ??= []).push(value); break;
      case "ST": case "S":  (result.state ??= []).push(value); break;
      case "L":             (result.locality ??= []).push(value); break;
      case "EMAILADDRESS": case "E": (result.emailAddress ??= []).push(value); break;
    }
  }
  return result;
}

function splitX509Name(nameStr: string): string[] {
  const parts: string[] = [];
  let current = "";
  let escaped = false;
  for (const ch of nameStr.replace(/\r?\n/g, "\n")) {
    if (escaped) {
      current += "\\" + ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "\n" || ch === ",") {
      if (current.trim()) parts.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (escaped) current += "\\";
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function unescapeX509Value(value: string): string {
  return value.replace(/\\([,=+<>#;"\\])/g, "$1");
}

function parseForgeName(attributes: forge.pki.CertificateField[], fallback: string): CertificateSubject {
  if (!attributes.length) return parseX509Name(fallback);
  const result: CertificateSubject = {};
  for (const attr of attributes) {
    const oid = attr.type;
    const value = String(attr.value);
    switch (oid) {
      case "2.5.4.3": result.commonName = value; break;
      case "2.5.4.10": (result.organization ??= []).push(value); break;
      case "2.5.4.11": (result.organizationalUnit ??= []).push(value); break;
      case "2.5.4.6": (result.country ??= []).push(value); break;
      case "2.5.4.8": (result.state ??= []).push(value); break;
      case "2.5.4.7": (result.locality ??= []).push(value); break;
      case "1.2.840.113549.1.9.1": (result.emailAddress ??= []).push(value); break;
    }
  }
  return result;
}

function parseSubjectAltNames(altNameStr: string): SubjectAlternativeName[] {
  if (!altNameStr) return [];
  const results: SubjectAlternativeName[] = [];

  for (const entry of altNameStr.split(/,\s*/)) {
    const colon = entry.indexOf(":");
    if (colon < 0) continue;
    const type = entry.slice(0, colon).trim().toLowerCase();
    const value = entry.slice(colon + 1).trim();

    if (type === "dns")        results.push({ type: "dns", value });
    else if (type === "ip" || type === "ip address") results.push({ type: "ip", value });
    else if (type === "email") results.push({ type: "email", value });
    else if (type === "uri")   results.push({ type: "uri", value });
  }
  return results;
}

function getPublicKeyInfo(key: crypto.KeyObject): { algorithm: string; keySize?: number } {
  try {
    const type = (key.asymmetricKeyType ?? "unknown").toUpperCase();
    const details = key.asymmetricKeyDetails ?? {};
    const keySize = "modulusLength" in details ? (details.modulusLength as number) : undefined;
    const curve = "namedCurve" in details ? ` (${details.namedCurve})` : "";
    return { algorithm: type + curve, keySize };
  } catch {
    return { algorithm: "unknown" };
  }
}


function buildExtensions(x509: crypto.X509Certificate, cert: forge.pki.Certificate | undefined): CertificateExtension[] {
  const exts = cert?.extensions.map(ext => {
    const anyExt = ext as Record<string, unknown>;
    const oid = String(anyExt.id ?? extensionOidByName(ext.name) ?? "unknown");
    return {
      oid,
      name: OID_NAMES[oid] ?? ext.name ?? oid,
      critical: Boolean(ext.critical),
      value: describeExtension(ext),
    };
  }) ?? [];

  if (x509.subjectAltName && !exts.some(e => e.oid === "2.5.29.17")) {
    exts.push({ oid: "2.5.29.17", name: "Subject Alternative Name", critical: false, value: x509.subjectAltName });
  }

  const ku = normalizeKeyUsage(x509.keyUsage);
  if (ku.length && !exts.some(e => e.oid === "2.5.29.15")) {
    exts.push({ oid: "2.5.29.15", name: "Key Usage", critical: true, value: ku.join(", ") });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const eku: string[] = (x509 as any).extendedKeyUsage ?? [];
  if (eku.length && !exts.some(e => e.oid === "2.5.29.37")) {
    exts.push({ oid: "2.5.29.37", name: "Extended Key Usage", critical: false, value: eku.join(", ") });
  }

  if (x509.infoAccess && !exts.some(e => e.oid === "1.3.6.1.5.5.7.1.1")) {
    exts.push({ oid: "1.3.6.1.5.5.7.1.1", name: "Authority Information Access", critical: false, value: x509.infoAccess });
  }

  return exts;
}

function extensionOidByName(name?: string): string | undefined {
  if (name && FORGE_EXTENSION_OIDS[name]) return FORGE_EXTENSION_OIDS[name];
  return Object.entries(OID_NAMES).find(([, n]) => n === name)?.[0];
}

function describeExtension(ext: forge.pki.Certificate["extensions"][number]): string {
  const anyExt = ext as Record<string, unknown>;
  if (ext.name === "basicConstraints") {
    return `CA: ${Boolean(anyExt.cA)}${typeof anyExt.pathLenConstraint === "number" ? `, pathLen: ${anyExt.pathLenConstraint}` : ""}`;
  }
  if (ext.name === "keyUsage") {
    return Object.entries(anyExt).filter(([, v]) => v === true).map(([k]) => k).join(", ");
  }
  if (ext.name === "extKeyUsage") {
    return Object.entries(anyExt).filter(([, v]) => v === true).map(([k]) => k).join(", ");
  }
  if (ext.name === "subjectAltName" || ext.name === "issuerAltName") {
    const altNames = anyExt.altNames as Array<{ type?: number; value?: string; ip?: string }> | undefined;
    return altNames?.map(a => a.value ?? a.ip ?? `type ${a.type}`).join(", ") ?? "";
  }
  if (ext.value) return Buffer.from(ext.value, "binary").toString("hex").toUpperCase();
  return JSON.stringify(anyExt, (_key, value) => typeof value === "string" && value.length > 256 ? `${value.slice(0, 256)}…` : value);
}

function parseKeyUsage(cert: forge.pki.Certificate): string[] | undefined {
  const ext = cert.extensions.find(e => (e as { id?: string }).id === "2.5.29.15" || e.name === "keyUsage") as Record<string, unknown> | undefined;
  if (!ext) return undefined;
  const names = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
  return names.filter(name => ext[name] === true);
}

function parseBasicConstraints(cert: forge.pki.Certificate): { ca: boolean; pathLenConstraint?: number } | undefined {
  const ext = cert.extensions.find(e => (e as { id?: string }).id === "2.5.29.19" || e.name === "basicConstraints") as Record<string, unknown> | undefined;
  if (!ext) return undefined;
  const result: { ca: boolean; pathLenConstraint?: number } = { ca: Boolean(ext.cA) };
  if (typeof ext.pathLenConstraint === "number") result.pathLenConstraint = ext.pathLenConstraint;
  return result;
}

function extensionValue(cert: forge.pki.Certificate, oid: string): string | undefined {
  const ext = cert.extensions.find(e => (e as { id?: string }).id === oid);
  return ext ? describeExtension(ext) : undefined;
}

function validateCertificate(
  x509: crypto.X509Certificate,
  subject: CertificateSubject,
  keyUsage: string[],
  extendedKeyUsage: string[],
  extensions: CertificateExtension[],
  basicConstraints?: { ca: boolean; pathLenConstraint?: number }
): CertificateFinding[] {
  const findings: CertificateFinding[] = [];
  const now = Date.now();
  if (new Date(x509.validTo).getTime() < now) findings.push({ severity: "error", message: "Certificate is expired.", rfc: "RFC 5280 §4.1.2.5" });
  if (new Date(x509.validFrom).getTime() > now) findings.push({ severity: "error", message: "Certificate is not yet valid.", rfc: "RFC 5280 §4.1.2.5" });
  if (!subject.commonName && !x509.subjectAltName) findings.push({ severity: "warning", message: "Certificate has neither subject CN nor SAN.", rfc: "RFC 5280 §4.1.2.6, §4.2.1.6" });
  if (basicConstraints?.ca && !keyUsage.includes("keyCertSign")) findings.push({ severity: "warning", message: "CA certificate lacks keyCertSign key usage.", rfc: "RFC 5280 §4.2.1.3, §4.2.1.9" });
  if (!basicConstraints?.ca && keyUsage.includes("keyCertSign")) findings.push({ severity: "warning", message: "End-entity certificate includes keyCertSign.", rfc: "RFC 5280 §4.2.1.3" });
  if (extendedKeyUsage.includes("serverAuth") && !x509.subjectAltName) findings.push({ severity: "warning", message: "TLS server certificate should include DNS/IP subjectAltName.", rfc: "RFC 6125 §6.4.4" });
  for (const ext of extensions) {
    if (ext.oid === "unknown") findings.push({ severity: "info", message: `Unrecognized extension: ${ext.name}.`, rfc: "RFC 5280 §4.2" });
  }
  return findings;
}

function safeCA(x509: crypto.X509Certificate): boolean {
  try { return x509.ca; } catch { return false; }
}

function formatSerial(serial: string): string {
  // Node returns hex string, format as colon-separated pairs
  return (serial.length % 2 === 0 ? serial : "0" + serial)
    .match(/.{1,2}/g)!
    .join(":")
    .toUpperCase();
}
