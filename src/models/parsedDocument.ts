import { CertificateInfo } from "./certificate";
import { CsrInfo } from "../parsers/csrParser";
import { KeyInfo } from "../parsers/keyParser";

export interface CertificateDocument {
  type: "certificates";
  items: CertificateInfo[];
}

export interface CsrDocument {
  type: "csr";
  items: CsrInfo[];
}

export interface CrlDocument {
  type: "crl";
  issuer: string;
  thisUpdate: string;
  nextUpdate: string;
  revokedCount: number;
  rawPem: string;
}

export interface ErrorDocument {
  type: "error";
  message: string;
  detail?: string;
}

export interface KeyDocument {
  type: "keys";
  items: KeyInfo[];
}

export type ParsedDocument =
  | CertificateDocument
  | CsrDocument
  | CrlDocument
  | KeyDocument
  | ErrorDocument;
