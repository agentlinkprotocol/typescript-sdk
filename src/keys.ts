import { ed25519 } from "@noble/curves/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import { base32NoPadLower, bytesToHex, hexToBytes, randomBytes } from "./bytes.js";

export const AGENT_ID_PREFIX = "alp1";

/** AgentId = "alp1" + lowercase base32 (no padding) of blake3(pubkey)[0..20]. */
export function agentIdFromPubkey(pubkey: Uint8Array): string {
  return AGENT_ID_PREFIX + base32NoPadLower(blake3(pubkey).slice(0, 20));
}

export function isAgentId(s: string): boolean {
  return s.startsWith(AGENT_ID_PREFIX) && s.length === 36 && /^[a-z2-7]+$/.test(s.slice(4));
}

/**
 * An agent's Ed25519 identity. The seed never leaves the agent's process: the SDK signs here,
 * the node only countersigns.
 */
export class AgentKey {
  readonly seed: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly agentId: string;

  private constructor(seed: Uint8Array) {
    if (seed.length !== 32) throw new Error("seed must be 32 bytes");
    this.seed = seed;
    this.publicKey = ed25519.getPublicKey(seed);
    this.agentId = agentIdFromPubkey(this.publicKey);
  }

  static generate(): AgentKey {
    return new AgentKey(randomBytes(32));
  }

  static fromSeed(seed: Uint8Array | string): AgentKey {
    return new AgentKey(typeof seed === "string" ? hexToBytes(seed) : seed);
  }

  get publicKeyHex(): string {
    return bytesToHex(this.publicKey);
  }

  /** Export the seed (hex). Store it like a password: without it the agent is gone. */
  exportSeed(): string {
    return bytesToHex(this.seed);
  }

  sign(message: Uint8Array): Uint8Array {
    return ed25519.sign(message, this.seed);
  }
}

export function verify(pubkey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, pubkey);
  } catch {
    return false;
  }
}
