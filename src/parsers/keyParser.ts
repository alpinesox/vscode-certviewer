import * as crypto from "crypto";

export interface KeyInfo {
  kind: "public" | "private";
  algorithm: string;
  keySize?: number;
  curve?: string;
  format: string;
  publicKeyPem?: string;
}

export function parseKeyFile(raw: Uint8Array, filename: string): KeyInfo[] {
  const text = Buffer.from(raw).toString("utf8");
  const isPrivate = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(text);
  const isPublic = /-----BEGIN (?:[A-Z ]+ )?PUBLIC KEY-----/.test(text);
  const key = isPrivate ? crypto.createPrivateKey(text) : isPublic ? crypto.createPublicKey(text) : crypto.createPublicKey(Buffer.from(raw));
  const details = key.asymmetricKeyDetails ?? {};
  const publicKeyPem = key.type === "private"
    ? crypto.createPublicKey(key).export({ type: "spki", format: "pem" }).toString()
    : key.export({ type: "spki", format: "pem" }).toString();
  return [{
    kind: key.type === "private" ? "private" : "public",
    algorithm: (key.asymmetricKeyType ?? "unknown").toUpperCase(),
    keySize: "modulusLength" in details ? details.modulusLength : undefined,
    curve: "namedCurve" in details ? details.namedCurve : undefined,
    format: filename.toLowerCase().endsWith(".der") ? "DER" : "PEM",
    publicKeyPem,
  }];
}
