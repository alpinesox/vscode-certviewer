import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { LintWorkerClient } from "../../parsers/lintWorkerClient";

const WORKER_PATH = path.resolve(__dirname, "../../workers/lintWorker.js");
const CERTIFICATE_PATH = path.resolve(__dirname, "../fixtures/certs/self-signed.pem");

suite("LintWorkerClient", () => {
  test("parses valid and invalid inputs concurrently in the worker", async () => {
    const client = new LintWorkerClient(WORKER_PATH);
    try {
      const pem = fs.readFileSync(CERTIFICATE_PATH);
      const [valid, invalid] = await Promise.all([
        client.parse(pem, "self-signed.pem"),
        client.parse(Buffer.from("not a certificate"), "invalid.pem"),
      ]);

      assert.strictEqual(valid.type, "certificates");
      if (valid.type !== "certificates") throw new Error("Expected a certificate document");
      assert.strictEqual(valid.items[0].subject.commonName, "self-signed.example.com");
      assert.ok(Array.isArray(valid.items[0].findings));
      assert.strictEqual(invalid.type, "error");
    } finally {
      client.dispose();
    }
  });

  test("rejects pending requests when disposed", async () => {
    const client = new LintWorkerClient(WORKER_PATH);
    const pending = client.parse(fs.readFileSync(CERTIFICATE_PATH), "self-signed.pem");
    client.dispose();
    await assert.rejects(pending, /disposed/i);
  });
});
