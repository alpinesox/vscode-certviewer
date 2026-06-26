import * as path from "path";
import * as vscode from "vscode";
import { CertificateFinding, CertificateFindingSeverity } from "../models/certificate";
import { ParsedDocument } from "../models/parsedDocument";
import { parseDocument } from "../parsers/documentParser";

const SUPPORTED_EXTENSIONS = new Set([
  ".pem", ".cer", ".crt", ".der", ".crl", ".p7b", ".p7c", ".p7", ".csr", ".key", ".pub", ".jwk",
]);

export class CertDiagnosticsProvider implements vscode.Disposable {
  private readonly collection = vscode.languages.createDiagnosticCollection("certview");
  private readonly disposables: vscode.Disposable[] = [];

  constructor() {
    this.disposables.push(
      this.collection,
      vscode.workspace.onDidOpenTextDocument(doc => { void this.updateTextDocument(doc); }),
      vscode.workspace.onDidSaveTextDocument(doc => { void this.updateTextDocument(doc); }),
      vscode.workspace.onDidChangeTextDocument(event => { void this.updateTextDocument(event.document); }),
      vscode.workspace.onDidCloseTextDocument(doc => this.collection.delete(doc.uri))
    );

    for (const doc of vscode.workspace.textDocuments) {
      void this.updateTextDocument(doc);
    }
  }

  async updateUri(uri: vscode.Uri): Promise<void> {
    if (!isSupportedUri(uri)) return;
    try {
      const raw = await vscode.workspace.fs.readFile(uri);
      this.setDiagnostics(uri, parseDocument(raw, uri.fsPath));
    } catch (error) {
      this.collection.set(uri, [diagnosticFromError(error)]);
    }
  }

  dispose(): void {
    for (const disposable of this.disposables) disposable.dispose();
  }

  private async updateTextDocument(doc: vscode.TextDocument): Promise<void> {
    if (!isSupportedUri(doc.uri)) return;
    if (doc.isUntitled) return;
    try {
      const raw = Buffer.from(doc.getText(), "utf8");
      this.setDiagnostics(doc.uri, parseDocument(raw, doc.uri.fsPath));
    } catch (error) {
      this.collection.set(doc.uri, [diagnosticFromError(error)]);
    }
  }

  private setDiagnostics(uri: vscode.Uri, parsed: ParsedDocument): void {
    if (parsed.type === "certificates") {
      this.collection.set(uri, parsed.items.flatMap((cert, certIndex) =>
        cert.findings.map(finding => diagnosticFromFinding(finding, certIndex, cert.subject.commonName ?? cert.serialNumber))
      ));
      return;
    }

    if (parsed.type === "error") {
      this.collection.set(uri, [new vscode.Diagnostic(new vscode.Range(0, 0, 0, 1), parsed.detail ?? parsed.message, vscode.DiagnosticSeverity.Error)]);
      return;
    }

    this.collection.delete(uri);
  }
}

function isSupportedUri(uri: vscode.Uri): boolean {
  return uri.scheme === "file" && SUPPORTED_EXTENSIONS.has(path.extname(uri.fsPath).toLowerCase());
}

function diagnosticFromFinding(finding: CertificateFinding, certIndex: number, label: string): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(0, 0, 0, 1),
    `Certificate ${certIndex + 1} (${label}): ${finding.message}${finding.rfc ? ` (${finding.rfc})` : ""}`,
    diagnosticSeverity(finding.severity)
  );
  diagnostic.source = "CertView";
  diagnostic.code = finding.rfc;
  return diagnostic;
}

function diagnosticFromError(error: unknown): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(0, 0, 0, 1),
    error instanceof Error ? error.message : String(error),
    vscode.DiagnosticSeverity.Error
  );
  diagnostic.source = "CertView";
  return diagnostic;
}

function diagnosticSeverity(severity: CertificateFindingSeverity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "error": return vscode.DiagnosticSeverity.Error;
    case "warning": return vscode.DiagnosticSeverity.Warning;
    case "info": return vscode.DiagnosticSeverity.Information;
  }
}
