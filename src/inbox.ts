/**
 * Sealed mailbox messages. Layout: eph_pub(32) || nonce(24) || xchacha20poly1305(ct);
 * key = blake3("alp-seal-v1" || dh || eph_pub || recipient_ed25519_pub).
 */
import { ed25519, edwardsToMontgomeryPriv, edwardsToMontgomeryPub, x25519 } from "@noble/curves/ed25519";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { DOMAIN, domainHash, signingHash } from "./canon.js";
import { bytesToHex, concat, hexToBytes, randomBytes, u64be, utf8 } from "./bytes.js";
import { AgentKey } from "./keys.js";
import type { CborValue } from "./cbor.js";

export const INBOX_MAX_MESSAGE_BYTES = 64 * 1024;

export function seal(recipientEdPub: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (plaintext.length + 32 + 24 + 16 > INBOX_MAX_MESSAGE_BYTES) throw new Error("message too large");
  const ephPriv = randomBytes(32);
  const ephPub = x25519.getPublicKey(ephPriv);
  const dh = x25519.getSharedSecret(ephPriv, edwardsToMontgomeryPub(recipientEdPub));
  const key = domainHash(DOMAIN.seal, concat(dh, ephPub, recipientEdPub));
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(plaintext);
  return concat(ephPub, nonce, ct);
}

export function open(recipient: AgentKey, sealed: Uint8Array): Uint8Array {
  if (sealed.length < 32 + 24 + 16) throw new Error("sealed box too short");
  const ephPub = sealed.slice(0, 32);
  const nonce = sealed.slice(32, 56);
  const ct = sealed.slice(56);
  const dh = x25519.getSharedSecret(edwardsToMontgomeryPriv(recipient.seed), ephPub);
  const key = domainHash(DOMAIN.seal, concat(dh, ephPub, recipient.publicKey));
  return xchacha20poly1305(key, nonce).decrypt(ct);
}

export function fetchAuthHash(agentId: string, nonce: number | bigint): Uint8Array {
  return domainHash(DOMAIN.inboxAck, concat(utf8(agentId), u64be(nonce)));
}

export function signFetch(agent: AgentKey, nonce: number | bigint): string {
  return bytesToHex(agent.sign(fetchAuthHash(agent.agentId, nonce)));
}

export interface InboxAck {
  agent_id: string;
  agent_pubkey: string;
  message_ids: string[];
  issued_at: number;
  sig: string;
}

export function makeAck(agent: AgentKey, messageIds: string[], issuedAt: number): InboxAck {
  const unsigned: CborValue = { agent_id: agent.agentId, agent_pubkey: agent.publicKey, message_ids: messageIds.map(hexToBytes), issued_at: issuedAt };
  const sig = bytesToHex(agent.sign(signingHash(DOMAIN.inboxAck, unsigned)));
  return { agent_id: agent.agentId, agent_pubkey: agent.publicKeyHex, message_ids: messageIds, issued_at: issuedAt, sig };
}

export { ed25519 };
