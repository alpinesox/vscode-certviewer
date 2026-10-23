import * as path from "path";
import { parentPort } from "worker_threads";
import { ParsedDocument } from "../models/parsedDocument";
import { parseDocument } from "../parsers/documentParser";

interface LintRequest {
  id: number;
  filename: string;
  raw: Uint8Array;
}

if (!parentPort) throw new Error("Lint worker must run inside a worker thread.");

parentPort.on("message", (request: LintRequest) => {
  let document: ParsedDocument;
  try {
    document = parseDocument(Buffer.from(request.raw), request.filename);
  } catch (error) {
    document = {
      type: "error",
      message: `Failed to parse ${path.basename(request.filename)}`,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
  parentPort?.postMessage({ id: request.id, document });
});
