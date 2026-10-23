import { blake3 } from "@noble/hashes/blake3";
import { encode, type CborValue } from "./cbor.js";
import { concat, utf8 } from "./bytes.js";

/** Signing domains. A signature covers blake3(domain || cbor(unsigned view)). */
export const DOMAIN = {
  card: "alp-card-v1",
  ephemeral: "alp-ephemeral-v1",
  revocation: "alp-revocation-v1",
  receipt: "alp-receipt-v1",
  opcert: "alp-opcert-v1",
  nodeSig: "alp-node-sig-v1",
  ledger: "alp-ledger-v1",
  inboxAck: "alp-inbox-ack-v1",
  vault: "alp-vault-v1",
  seal: "alp-seal-v1",
} as const;

export function domainHash(domain: string, payload: Uint8Array): Uint8Array {
  return blake3(concat(utf8(domain), payload));
}

export function signingHash(domain: string, unsigned: CborValue): Uint8Array {
  return domainHash(domain, encode(unsigned));
}

export function hash(bytes: Uint8Array): Uint8Array {
  return blake3(bytes);
}
