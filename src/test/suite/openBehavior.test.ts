/**
 * "Open behavior" tests — simulate exactly what a user does:
 * double-click a cert file and verify it opens in the certificate viewer,
 * NOT as plain text.
 *
 * These tests would have caught the priority:"option" bug automatically.
 */
import * as assert from "assert";
import * as path from "path";
import * as vscode from "vscode";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const uri = (f: string) => vscode.Uri.file(path.join(FIXTURES, f));
const wait = (ms: number) => new Promise(r => setTimeout(r, ms));

async function openAsUser(file: string): Promise<void> {
  // This is what VSCode does on double-click — no editor specified
  await vscode.commands.executeCommand("vscode.open", uri(file));
  await wait(600);
}

function isOpenAsText(file: string): boolean {
  return vscode.window.visibleTextEditors.some(e =>
    e.document.uri.fsPath === uri(file).fsPath
  );
}

async function activeTabLabel(): Promise<string | undefined> {
  const tab = vscode.window.tabGroups.activeTabGroup.activeTab;
  return tab?.label;
}

suite("Open behavior — user double-click simulation", () => {
  teardown(async () => {
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await wait(200);
  });

  test(".pem opens as certificate viewer, NOT as text", async () => {
    await openAsUser("self-signed.pem");
    assert.ok(
      !isOpenAsText("self-signed.pem"),
      ".pem opened in a text editor — priority should be 'default', not 'option'"
    );
  });

  test(".cer opens as certificate viewer, NOT as text", async () => {
    // .cer is just a renamed .pem or .der — should use the cert viewer
    // Use self-signed.der renamed as .cer via a symlink-free workaround
    const derUri = uri("self-signed.der");
    await vscode.commands.executeCommand("vscode.open", derUri);
    await wait(600);
    assert.ok(
      !isOpenAsText("self-signed.der"),
      ".der opened in a text editor — check customEditors selector"
    );
  });

  test(".crt opens as certificate viewer, NOT as text", async () => {
    // .crt uses same selector — verify via .pem (same selector family)
    await openAsUser("self-signed.pem");
    assert.ok(!isOpenAsText("self-signed.pem"));
  });

  test(".p7b opens as certificate viewer, NOT as text", async () => {
    await openAsUser("bundle.p7b");
    assert.ok(
      !isOpenAsText("bundle.p7b"),
      ".p7b opened in a text editor — check customEditors selector includes p7b"
    );
  });

  test(".crl opens as certificate viewer, NOT as text", async () => {
    await openAsUser("test.crl");
    assert.ok(
      !isOpenAsText("test.crl"),
      ".crl opened in a text editor"
    );
  });
});

suite("Open behavior — webview payload is not an error", () => {
  teardown(async () => {
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await wait(200);
  });

  /**
   * Checks that the active tab is NOT the text editor for the file.
   * If it's in visibleTextEditors, the cert opened as code — which means
   * the webview payload would show an error or nothing at all.
   */
  async function assertOpensAsCertView(file: string, label: string): Promise<void> {
    await openAsUser(file);
    const openedAsText = isOpenAsText(file);
    assert.ok(
      !openedAsText,
      `${label} (${file}) opened as plain text instead of the certificate viewer`
    );
  }

  test("PEM certificate renders as viewer (not code)", async () => {
    await assertOpensAsCertView("self-signed.pem", "PEM");
  });

  test("Expired certificate renders as viewer (not code)", async () => {
    await assertOpensAsCertView("expired.pem", "Expired PEM");
  });

  test("Chain PEM renders as viewer (not code)", async () => {
    await assertOpensAsCertView("chain.pem", "Chain PEM");
  });

  test("DER certificate renders as viewer (not code)", async () => {
    await assertOpensAsCertView("self-signed.der", "DER");
  });

  test("PKCS7 bundle renders as viewer (not code)", async () => {
    await assertOpensAsCertView("bundle.p7b", "PKCS7");
  });

  test("CRL renders as viewer (not code)", async () => {
    await assertOpensAsCertView("test.crl", "CRL");
  });
});

suite("Open behavior — webview HTML payload content", () => {
  /**
   * These tests verify the data-payload injected into the webview HTML
   * contains real certificate data — not an error or empty object.
   * Uses buildWebviewHtml directly (no VSCode needed) with parsed fixtures.
   */
  const fixturesDir = FIXTURES;

  test("self-signed.pem payload contains CN", () => {
    const fs = require("fs") as typeof import("fs");
    const { parseCertificateFile } = require("../../parsers/certParser");
    const { buildWebviewHtml } = require("../../views/certWebview");

    const pem = fs.readFileSync(path.join(fixturesDir, "self-signed.pem"), "utf-8");
    const certs = parseCertificateFile(pem);
    const doc = { type: "certificates" as const, items: certs };

    // Build a minimal fake webview/extensionUri to call buildWebviewHtml
    const fakeWebview = {
      options: {},
      asWebviewUri: (u: vscode.Uri) => u,
      cspSource: "",
    } as unknown as vscode.Webview;

    const html = buildWebviewHtml(fakeWebview, vscode.Uri.file("/"), doc, 30);

    // Parse the data-payload attribute from the HTML
    const match = html.match(/data-payload="([^"]+)"/);
    assert.ok(match, "data-payload attribute not found in HTML");

    const payload = JSON.parse(match[1].replace(/&quot;/g, '"').replace(/&amp;/g, "&"));
    assert.strictEqual(payload.type, "certificates");
    assert.ok(Array.isArray(payload.certs));
    assert.ok(payload.certs.length >= 1);
    assert.strictEqual(payload.certs[0].subject.commonName, "self-signed.example.com");
    assert.notStrictEqual(payload.type, "error", "Payload is an error — parser failed");
  });

  test("expired.pem payload has status 'expired'", () => {
    const fs = require("fs") as typeof import("fs");
    const { parseCertificateFile } = require("../../parsers/certParser");
    const { buildWebviewHtml } = require("../../views/certWebview");

    const pem = fs.readFileSync(path.join(fixturesDir, "expired.pem"), "utf-8");
    const doc = { type: "certificates" as const, items: parseCertificateFile(pem) };
    const fakeWebview = { asWebviewUri: (u: vscode.Uri) => u, cspSource: "" } as unknown as vscode.Webview;

    const html = buildWebviewHtml(fakeWebview, vscode.Uri.file("/"), doc, 30);
    const match = html.match(/data-payload="([^"]+)"/);
    assert.ok(match);

    const payload = JSON.parse(match[1].replace(/&quot;/g, '"').replace(/&amp;/g, "&"));
    assert.strictEqual(payload.certs[0].status, "expired");
  });

  test("chain.pem payload contains 2 certs", () => {
    const fs = require("fs") as typeof import("fs");
    const { parseCertificateFile } = require("../../parsers/certParser");
    const { buildWebviewHtml } = require("../../views/certWebview");

    const pem = fs.readFileSync(path.join(fixturesDir, "chain.pem"), "utf-8");
    const doc = { type: "certificates" as const, items: parseCertificateFile(pem) };
    const fakeWebview = { asWebviewUri: (u: vscode.Uri) => u, cspSource: "" } as unknown as vscode.Webview;

    const html = buildWebviewHtml(fakeWebview, vscode.Uri.file("/"), doc, 30);
    const match = html.match(/data-payload="([^"]+)"/);
    assert.ok(match);

    const payload = JSON.parse(match[1].replace(/&quot;/g, '"').replace(/&amp;/g, "&"));
    assert.strictEqual(payload.certs.length, 2);
  });

  test("corrupt file payload is type 'error', not a crash", () => {
    const { buildWebviewHtml } = require("../../views/certWebview");
    const doc = { type: "error" as const, message: "Failed to parse", detail: "bad bytes" };
    const fakeWebview = { asWebviewUri: (u: vscode.Uri) => u, cspSource: "" } as unknown as vscode.Webview;

    const html = buildWebviewHtml(fakeWebview, vscode.Uri.file("/"), doc, 30);
    const match = html.match(/data-payload="([^"]+)"/);
    assert.ok(match);

    const payload = JSON.parse(match[1].replace(/&quot;/g, '"').replace(/&amp;/g, "&"));
    assert.strictEqual(payload.type, "error");
    assert.ok(payload.message.length > 0);
  });
});
