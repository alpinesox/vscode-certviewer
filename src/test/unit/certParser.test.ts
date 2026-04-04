import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { parseCertificateFile } from "../../parsers/certParser";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const readText = (f: string): string => fs.readFileSync(path.join(FIXTURES, f), "utf-8");
const readBin = (f: string): Buffer => fs.readFileSync(path.join(FIXTURES, f));

suite("certParser — error cases", () => {
  test("throws on empty string", () => {
    assert.throws(() => parseCertificateFile(""), /No CERTIFICATE blocks found/);
  });

  test("throws when no CERTIFICATE block present", () => {
    assert.throws(
      () => parseCertificateFile("-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----"),
      /No CERTIFICATE blocks found/
    );
  });
});

suite("certParser — self-signed PEM", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("self-signed.pem"));
  });

  test("returns exactly one cert", () => {
    assert.strictEqual(certs.length, 1);
  });

  test("common name is correct", () => {
    assert.strictEqual(certs[0].subject.commonName, "self-signed.example.com");
  });

  test("is self-signed", () => {
    assert.strictEqual(certs[0].isSelfSigned, true);
  });

  test("has sha1 fingerprint", () => {
    assert.ok(certs[0].fingerprints.sha1.length > 0);
    assert.ok(/^[A-F0-9:]+$/.test(certs[0].fingerprints.sha1));
  });

  test("has sha256 fingerprint", () => {
    assert.ok(certs[0].fingerprints.sha256.length > 0);
    assert.ok(/^[A-F0-9:]+$/.test(certs[0].fingerprints.sha256));
  });

  test("has subjectAltNames", () => {
    const dns = certs[0].subjectAltNames.filter(s => s.type === "dns");
    assert.ok(dns.length >= 1);
    assert.ok(dns.some(s => s.value === "self-signed.example.com"));
  });

  test("has IP SAN 127.0.0.1", () => {
    const ips = certs[0].subjectAltNames.filter(s => s.type === "ip");
    assert.ok(ips.some(s => s.value === "127.0.0.1"));
  });

  test("has keyUsage", () => {
    assert.ok(certs[0].keyUsage.length > 0);
  });

  test("extendedKeyUsage is an array", () => {
    assert.ok(Array.isArray(certs[0].extendedKeyUsage));
  });

  test("has RSA public key", () => {
    assert.ok(certs[0].publicKeyAlgorithm.includes("RSA"));
  });

  test("has 2048-bit key", () => {
    assert.strictEqual(certs[0].publicKeySize, 2048);
  });

  test("has valid notBefore/notAfter dates", () => {
    assert.ok(certs[0].validity.notBefore instanceof Date);
    assert.ok(certs[0].validity.notAfter instanceof Date);
    assert.ok(certs[0].validity.notAfter > certs[0].validity.notBefore);
  });

  test("serialNumber is colon-separated hex", () => {
    assert.ok(/^[A-F0-9:]+$/.test(certs[0].serialNumber));
  });

  test("pem field is populated", () => {
    assert.ok(certs[0].pem.includes("BEGIN CERTIFICATE"));
  });
});

suite("certParser — CA cert", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("ca.pem"));
  });

  test("isCA is true", () => {
    assert.strictEqual(certs[0].isCA, true);
  });

  test("isSelfSigned is true", () => {
    assert.strictEqual(certs[0].isSelfSigned, true);
  });

  test("CN is Test CA", () => {
    assert.strictEqual(certs[0].subject.commonName, "Test CA");
  });

  test("organization is CertView Tests", () => {
    assert.deepStrictEqual(certs[0].subject.organization, ["CertView Tests"]);
  });
});

suite("certParser — chain PEM (2 certs)", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("chain.pem"));
  });

  test("returns 2 certs", () => {
    assert.strictEqual(certs.length, 2);
  });

  test("first cert is leaf", () => {
    assert.strictEqual(certs[0].subject.commonName, "leaf.example.com");
  });

  test("second cert is CA", () => {
    assert.strictEqual(certs[1].subject.commonName, "Test CA");
  });

  test("leaf is not self-signed", () => {
    assert.strictEqual(certs[0].isSelfSigned, false);
  });

  test("leaf issuer matches CA subject", () => {
    assert.strictEqual(certs[0].issuer.commonName, certs[1].subject.commonName);
  });
});

suite("certParser — expired cert", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("expired.pem"));
  });

  test("parses without throwing", () => {
    assert.ok(certs.length >= 1);
  });

  test("notAfter is in the past", () => {
    assert.ok(certs[0].validity.notAfter < new Date());
  });
});

suite("certParser — EC key cert", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("ec-key.pem"));
  });

  test("parses without throwing", () => {
    assert.ok(certs.length === 1);
  });

  test("public key algorithm is EC", () => {
    assert.ok(certs[0].publicKeyAlgorithm.includes("EC"));
  });

  test("has no key size (EC uses curve name)", () => {
    assert.ok(certs[0].publicKeyAlgorithm.includes("P-256") || certs[0].publicKeySize === undefined);
  });
});

suite("certParser — DER input", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readBin("self-signed.der"));
  });

  test("parses DER cert correctly", () => {
    assert.strictEqual(certs.length, 1);
    assert.strictEqual(certs[0].subject.commonName, "self-signed.example.com");
  });

  test("DER and PEM yield identical fingerprints", () => {
    const pemCerts = parseCertificateFile(readText("self-signed.pem"));
    assert.strictEqual(certs[0].fingerprints.sha256, pemCerts[0].fingerprints.sha256);
  });
});
