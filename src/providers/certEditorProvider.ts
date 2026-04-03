import * as vscode from "vscode";
import * as path from "path";
import { splitPemBlocks, isPemContent, isDerBuffer, detectFormat } from "../parsers/pemParser";
import { ParsedDocument } from "../models/parsedDocument";
import { buildWebviewHtml } from "../views/certWebview";

export class CertEditorProvider implements vscode.CustomReadonlyEditorProvider {
  public static readonly viewType = "certview.certEditor";

  constructor(private readonly context: vscode.ExtensionContext) {}

  public static register(context: vscode.ExtensionContext): vscode.Disposable {
    return vscode.window.registerCustomEditorProvider(
      CertEditorProvider.viewType,
      new CertEditorProvider(context),
      {
        webviewOptions: { retainContextWhenHidden: true },
        supportsMultipleEditorsPerDocument: false,
      }
    );
  }

  async openCustomDocument(
    uri: vscode.Uri,
    _openContext: vscode.CustomDocumentOpenContext,
    _token: vscode.CancellationToken
  ): Promise<vscode.CustomDocument> {
    return { uri, dispose: () => {} };
  }

  async resolveCustomEditor(
    document: vscode.CustomDocument,
    webviewPanel: vscode.WebviewPanel,
    _token: vscode.CancellationToken
  ): Promise<void> {
    webviewPanel.webview.options = { enableScripts: true };

    const config = vscode.workspace.getConfiguration("certview");
    const warningDays: number = config.get("warningDaysBeforeExpiry", 30);

    const parsed = await this.parseFile(document.uri);
    webviewPanel.webview.html = buildWebviewHtml(
      webviewPanel.webview,
      this.context.extensionUri,
      parsed,
      warningDays
    );

    webviewPanel.webview.onDidReceiveMessage(async (msg: { command: string; data?: string }) => {
      switch (msg.command) {
        case "copyText":
          if (msg.data) {
            await vscode.env.clipboard.writeText(msg.data);
            vscode.window.showInformationMessage("Copied to clipboard.");
          }
          break;
        case "openRaw":
          await vscode.commands.executeCommand("vscode.openWith", document.uri, "default");
          break;
      }
    });
  }

  private async parseFile(uri: vscode.Uri): Promise<ParsedDocument> {
    const raw = await vscode.workspace.fs.readFile(uri);
    const ext = path.extname(uri.fsPath).toLowerCase();

    try {
      // Text-based formats
      if (ext !== ".der" && !isDerBuffer(raw)) {
        const text = Buffer.from(raw).toString("utf-8");

        if (!isPemContent(text)) {
          // Some .cer files are actually DER despite the extension
          return this.parseDer(raw);
        }

        const format = detectFormat(text, ext);

        if (format === "X509 CRL") {
          return this.parseCrlPem(text);
        }

        // Default: CERTIFICATE
        return { type: "error", message: "Certificate parsing not available in this build.", detail: "" };
      }

      return this.parseDer(raw);

    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const stack = err instanceof Error ? err.stack ?? "" : "";
      return {
        type: "error",
        message: `Failed to parse ${path.basename(uri.fsPath)}`,
        detail: message + (stack ? `\n\n${stack.split("\n").slice(0, 5).join("\n")}` : ""),
      };
    }
  }

  private parseDer(_raw: Uint8Array): ParsedDocument {
    return { type: "error", message: "DER parsing not available in this build.", detail: "" };
  }

  private parseCrlPem(text: string): ParsedDocument {
    // Parse basic CRL info from the PEM
    const blocks = splitPemBlocks(text).filter(b => b.type === "X509 CRL");
    if (blocks.length === 0) {
      throw new Error("No X509 CRL block found.");
    }

    // Minimal DER inspection for issuer, thisUpdate, nextUpdate
    const der = Buffer.from(blocks[0].base64, "base64");
    return {
      type: "crl",
      issuer: extractCrlIssuer(der),
      thisUpdate: "See raw file",
      nextUpdate: "See raw file",
      revokedCount: -1,
      rawPem: blocks[0].pem,
    };
  }

}

// Minimal CRL issuer extraction — scans DER bytes for the first string-type value
function extractCrlIssuer(der: Buffer): string {
  try {
    // Walk DER bytes looking for UTF8String (0x0c) or PrintableString (0x13) tags
    for (let i = 0; i < der.length - 2; i++) {
      const tag = der[i];
      if (tag !== 0x0c && tag !== 0x13) continue;
      const len = der[i + 1];
      if (len >= 0x80 || i + 2 + len > der.length) continue;
      const str = der.slice(i + 2, i + 2 + len).toString("utf8");
      if (str.length > 0 && /^[\x20-\x7e\u00a0-\ufffd]+$/.test(str)) return str;
    }
  } catch { /* ignore */ }
  return "Unknown";
}
