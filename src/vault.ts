/**
 * Vault: the agent encrypts its memory with a key only its owner holds; the node splits the
 * ciphertext into Reed-Solomon shards (30, any 10 rebuild) which the agent signs one by one.
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { DOMAIN, signingHash } from "./canon.js";
import { bytesToHex, concat, hexToBytes, randomBytes, u64be, utf8 } from "./bytes.js";
import type { CborValue } from "./cbor.js";
import { AgentKey } from "./keys.js";
import { operatorCertCbor, type OperatorCert } from "./objects.js";

export const VAULT_MAX_BYTES = 256 * 1024 * 1024;

export class VaultKey {
  constructor(readonly key: Uint8Array) {
    if (key.length !== 32) throw new Error("vault key must be 32 bytes");
  }
  static generate(): VaultKey {
    return new VaultKey(randomBytes(32));
  }
  static fromHex(h: string): VaultKey {
    return new VaultKey(hexToBytes(h));
  }
  toHex(): string {
    return bytesToHex(this.key);
  }
}

function aad(agentId: string, snapshot: number | bigint): Uint8Array {
  return concat(utf8(agentId), u64be(snapshot));
}

/** nonce(24) || ciphertext, AAD = agent_id || snapshot. */
export function encryptSnapshot(key: VaultKey, agentId: string, snapshot: number, plaintext: Uint8Array): Uint8Array {
  if (plaintext.length > VAULT_MAX_BYTES) throw new Error("snapshot too large");
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key.key, nonce, aad(agentId, snapshot)).encrypt(plaintext);
  return concat(nonce, ct);
}

export function decryptSnapshot(key: VaultKey, agentId: string, snapshot: number, blob: Uint8Array): Uint8Array {
  return xchacha20poly1305(key.key, blob.slice(0, 24), aad(agentId, snapshot)).decrypt(blob.slice(24));
}

export interface UnsignedShard {
  index: number;
  total: number;
  data_shards: number;
  shard_hash: string;
  data: string;
}

export interface VaultShard extends UnsignedShard {
  agent_id: string;
  agent_pubkey: string;
  snapshot: number;
  expires_at: number;
  operator_cert: OperatorCert;
  agent_sig: string;
  node_sig: string;
}

export function shardUnsigned(s: Omit<VaultShard, "agent_sig" | "node_sig" | "operator_cert" | "data">): CborValue {
  return {
    agent_id: s.agent_id,
    agent_pubkey: hexToBytes(s.agent_pubkey),
    snapshot: s.snapshot,
    index: s.index,
    total: s.total,
    data_shards: s.data_shards,
    shard_hash: hexToBytes(s.shard_hash),
    expires_at: s.expires_at,
  };
}

export function signShards(agent: AgentKey, shards: UnsignedShard[], snapshot: number, expiresAt: number, operatorCert: OperatorCert): VaultShard[] {
  return shards.map((s) => {
    const base = { agent_id: agent.agentId, agent_pubkey: agent.publicKeyHex, snapshot, index: s.index, total: s.total, data_shards: s.data_shards, shard_hash: s.shard_hash, expires_at: expiresAt };
    const agent_sig = bytesToHex(agent.sign(signingHash(DOMAIN.vault, shardUnsigned(base))));
    return { ...base, data: s.data, operator_cert: operatorCert, agent_sig, node_sig: "00".repeat(64) };
  });
}

export { operatorCertCbor };
