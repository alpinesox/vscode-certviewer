# X509 Certificate Utility

**Inspect X509 certificates inside VS Code.**

---

## Features

- **X509 viewer** — subject, issuer, validity, serial number, and extensions at a glance
- **Chain support** — multi-certificate files are displayed as a chain
- **Expiry warnings** — certificates expiring soon are highlighted
- **Certificate Explorer** — sidebar panel listing files in workspace
- **Syntax highlighting** — PEM blocks get colorization

### Supported file types

| Extension | Format |
|-----------|--------|
| `.pem` | PEM (text, single or chain) |
| `.cer` `.crt` | DER or PEM certificate |
| `.der` | DER binary certificate |
| `.p7b` `.p7c` `.p7` | PKCS#7 certificate bundle |
| `.crl` | Certificate Revocation List |
| `.csr` | Certificate Signing Request (PKCS#10) |
| `.p12` `.pfx` | PKCS#12 keystore (certificates extracted; password prompt if protected) |

---

## Usage

1. Open a certificate file — the utility opens automatically
2. Use the **Certificates** panel in the Explorer sidebar
3. Right-click a file → **X509 Certificate Utility: Open**

---

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `certview.showExpiredWarning` | `true` | Highlight expired certificates |
| `certview.warningDaysBeforeExpiry` | `30` | Days before expiry to show warning |
| `certview.defaultView` | `"summary"` | Default view tab |

---

## Requirements

- VS Code 1.85 or later
- Local parsing — no network access required

---

## Known Issues

- Large CRL files may take a moment to parse

---

## Release Notes

### 0.3.0

- Added CSR (`.csr`) support — Certificate Signing Request viewer (subject, public key, signature algorithm)
- Added P12/PFX (`.p12`, `.pfx`) support — extracts and displays certificates from PKCS#12 keystores, with password prompt for protected files

### 0.1.4

- Improved metadata and stability
- Local certificate viewing
