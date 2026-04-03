import * as assert from "assert";
import { formatDate, formatRelativeExpiry, getCertDisplayName, subjectToString } from "../../utils/formatters";
import { CertificateSubject } from "../../models/certificate";

suite("formatDate", () => {
  test("formats a known date", () => {
    const d = new Date("2025-06-15T12:00:00Z");
    const result = formatDate(d);
    assert.ok(result.includes("2025"), `Expected year 2025 in: ${result}`);
    assert.ok(result.includes("Jun"), `Expected month Jun in: ${result}`);
  });

  test("returns a non-empty string", () => {
    assert.ok(formatDate(new Date()).length > 0);
  });
});

suite("formatRelativeExpiry", () => {
  test("returns 'Expires today' for a date in less than 24h", () => {
    const soon = new Date(Date.now() + 1000 * 60 * 60);
    assert.strictEqual(formatRelativeExpiry(soon), "Expires today");
  });

  test("returns 'Expired today' for a date just passed", () => {
    const past = new Date(Date.now() - 1000 * 60 * 60);
    assert.strictEqual(formatRelativeExpiry(past), "Expired today");
  });

  test("returns 'Expires in 1 day' for ~tomorrow", () => {
    const tomorrow = new Date(Date.now() + 1.5 * 24 * 60 * 60 * 1000);
    assert.strictEqual(formatRelativeExpiry(tomorrow), "Expires in 1 day");
  });

  test("returns 'Expired 1 day ago' for ~yesterday", () => {
    const yesterday = new Date(Date.now() - 1.5 * 24 * 60 * 60 * 1000);
    assert.strictEqual(formatRelativeExpiry(yesterday), "Expired 1 day ago");
  });

  test("returns plural days for multi-day future", () => {
    const future = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000);
    assert.strictEqual(formatRelativeExpiry(future), "Expires in 10 days");
  });

  test("returns plural days for multi-day past", () => {
    const past = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
    assert.strictEqual(formatRelativeExpiry(past), "Expired 10 days ago");
  });
});

suite("getCertDisplayName", () => {
  test("returns commonName when present", () => {
    const subject: CertificateSubject = { commonName: "example.com", organization: ["Acme"] };
    assert.strictEqual(getCertDisplayName(subject, "01:02:03"), "example.com");
  });

  test("falls back to organization when no CN", () => {
    const subject: CertificateSubject = { organization: ["Acme Corp"] };
    assert.strictEqual(getCertDisplayName(subject, "01:02:03"), "Acme Corp");
  });

  test("falls back to serial when no CN or org", () => {
    const subject: CertificateSubject = {};
    const result = getCertDisplayName(subject, "AABBCCDDEEFF");
    assert.ok(result.startsWith("Serial:"));
  });
});

suite("subjectToString", () => {
  test("formats full subject", () => {
    const subject: CertificateSubject = {
      commonName: "example.com",
      organization: ["Acme Corp"],
      country: ["US"],
    };
    const result = subjectToString(subject);
    assert.ok(result.includes("CN=example.com"));
    assert.ok(result.includes("O=Acme Corp"));
    assert.ok(result.includes("C=US"));
  });

  test("returns empty string for empty subject", () => {
    assert.strictEqual(subjectToString({}), "");
  });

  test("handles multiple organizations", () => {
    const subject: CertificateSubject = { organization: ["Org A", "Org B"] };
    const result = subjectToString(subject);
    assert.ok(result.includes("Org A"));
    assert.ok(result.includes("Org B"));
  });
});
