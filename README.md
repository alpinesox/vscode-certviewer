# X509 Certificate Utility

**Stop opening terminals just to inspect a certificate.**
View X.509 certificates, keystores, and signing requests directly inside VS Code — no OpenSSL commands needed.

![Certificate details view](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-cert-details.png)

---

## What it does

Double-click any certificate file and instantly see:

- **Subject & Issuer** — Common Name, Organization, Country, and more
- **Validity period** — clear expiry date with a visual status banner (valid / expiring soon / expired)
- **Fingerprints** — SHA-1 and SHA-256 with one-click copy
- **Public key** — algorithm and key size
- **Extensions** — SANs, Key Usage, Extended Key Usage

---

## Expiry warnings at a glance

Never get caught by a surprise certificate expiration. Files expiring within 30 days get a yellow warning banner; expired certificates show a red one.

![Expiry warning banner](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-expiry-warning.png)

---

## Certificate chains

Multi-certificate files (chains, P7B bundles) are displayed as tabbed panels — one tab per certificate in the chain.

![Certificate chain with tabs](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-chain-bundle.png)

---

## CA certificates

Self-signed and CA certificates are clearly identified.

![CA certificate view](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-ca-certificate.png)

---

## Certificate Revocation Lists

CRL files open with issuer and update timestamps — no more decoding DER by hand.

![CRL viewer](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-crl-viewer.png)

---

## Supported formats

| Extension | Format |
|-----------|--------|
| `.pem` | PEM — single certificate or chain |
| `.cer` `.crt` | DER or PEM certificate |
| `.der` | DER binary certificate |
| `.p7b` `.p7c` `.p7` | PKCS#7 certificate bundle |
| `.crl` | Certificate Revocation List |
| `.csr` | Certificate Signing Request (PKCS#10) |
| `.p12` `.pfx` | PKCS#12 keystore — password prompt if protected |

---

## Usage

- **Open a file** → the viewer opens automatically on double-click
- **Right-click** any supported file → *X509 Certificate Utility: Open*
- **Certificates panel** in the Explorer sidebar lists all cert files in the workspace

---

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `certview.warningDaysBeforeExpiry` | `30` | Days before expiry to show the warning banner |
| `certview.showExpiredWarning` | `true` | Highlight expired certificates |

---

## Requirements

- VS Code 1.85 or later
- Works fully offline — no network access, no telemetry

---

## Release Notes

### 0.3.1

- CI pipeline improvements and lint cleanup

### 0.3.0

- Added `.csr` support — Certificate Signing Request viewer
- Added `.p12` / `.pfx` support — extracts certificates from PKCS#12 keystores with password prompt

### 0.1.4

- Initial release — local certificate viewing
