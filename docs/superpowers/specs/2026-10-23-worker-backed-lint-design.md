# Worker-Backed Certificate Linting

## Goal

Keep all product linting off VS Code's extension-host thread while preserving the existing synchronous parser APIs for direct unit tests. The worker should process raw file bytes so private key material is parsed and linted locally without adding private-key fields to `ParsedDocument` or diagnostics.

## Scope and pull-request split

### MR 1: Worker architecture

- Add one persistent Node worker for parsing and linting requests.
- Route extension-host parsing paths through the worker, including cached file reads and live text diagnostics.
- Move the current lint rules, including the existing bounded P-384 scalar check, into the worker's execution path without changing their behavior.
- Bundle the worker as `out/workers/lintWorker.js` and terminate it during extension deactivation.
- Preserve the existing parsed-document result shape and diagnostic/webview behavior.

### MR 2: Additional key checks

Based on the worker architecture, add RSA Wiener-recovery checks and extend bounded EC small-scalar checks to the supported curves. Apply the checks to certificate public keys, CSR public keys, and supported public/private key files.

Shared-prime detection and repeated-ECDSA-nonce detection are out of scope because they require comparing a set of keys or signatures. EdDSA and ML-DSA receive no generic entropy claim; their key encodings remain subject to parser/runtime validation.

## Worker boundary

The extension host sends `{ requestId, filename, bytes }` to the worker. The worker calls the existing `parseDocument` pipeline and returns `{ requestId, document }`. Existing parser size and certificate-count limits remain in force inside that pipeline. The message protocol must return a parse error result for request failures, reject pending requests if the worker exits, and avoid a synchronous main-thread fallback.

One worker processes requests serially. This avoids pool management and preserves ordering; add a pool only if measurements show a throughput problem. When live-document parsing returns, diagnostics must check that the document version is still current before publishing results.

Private key bytes cross only the local worker-thread boundary for parsing; they are not included in returned parsed-document key models, findings, diagnostics, logs, or webview payloads. Encrypted private keys remain unopened as they are today.

## Integration

- `ParsedDocumentCache` accepts an asynchronous parser dependency and awaits it.
- `CertEditorProvider`, `CertTreeProvider`, and disk-backed diagnostics use the worker through the shared cache.
- Live text diagnostics send their current text bytes directly to the same worker and discard stale responses.
- The worker entry point is bundled alongside the extension and is also emitted at the same path by TypeScript compilation for integration tests.
- Worker lifecycle is owned by extension activation/deactivation; all pending requests must settle on worker failure or disposal.

## Validation

- Unit-test request/result matching, worker parse/lint results, error propagation, and disposal.
- Retain parser-level unit tests and add an integration test proving a weak-key diagnostic is published from the worker path.
- Run `pnpm lint`, `pnpm test:unit`, `pnpm test`, and `pnpm package:ci` per the upstream contribution guide.
- Update `CHANGELOG.md` under `Unreleased`. Include a screenshot if the lint-banner presentation changes.
