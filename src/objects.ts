/**
 * Signed objects of the Atlas, in their JSON (API) form and their canonical CBOR views.
 * Field order in the `*Unsigned` builders is the canonical order and must not change.
 */
import { DOMAIN, signingHash } from "./canon.js";
import { encode, type CborValue } from "./cbor.js";
import { bytesToHex, hexToBytes, randomBytes } from "./bytes.js";
import { AgentKey, agentIdFromPubkey, verify } from "./keys.js";

export const MODEL_V1 = "alp-embed-v1";
export const DAY = 86_400;
export const CARD_MAX_TTL = 90 * DAY;
export const EPHEMERAL_MAX_TTL = 7 * DAY;

export interface Filters {
  /** Geohash, precision 6 (~1 km), matched by prefix. */
  geohash?: string | null;
  /** Bitmask Monday (bit 0) .. Sunday (bit 6). */
  days?: number | null;
  /** ISO 639-1 codes, lowercase. */
  langs?: string[];
}

export interface OperatorCert {
  operator_pubkey: string;
  node_pubkey: string;
  issued_at: number;
  expires_at: number;
  sig: string;
}

export interface Card {
  agent_id: string;
  agent_pubkey: string;
  version: number;
  endpoints: string[];
  traits: string[];
  filters: Filters;
  model: string;
  map_version: number;
  issued_at: number;
  last_seen: number;
  expires_at: number;
  operator_cert: OperatorCert;
  agent_sig: string;
  node_sig: string;
}

export interface Ephemeral {
  agent_id: string;
  agent_pubkey: string;
  ephemeral_id: string;
  text: string;
  filters: Filters;
  valid_from: number;
  valid_until: number;
  operator_cert: OperatorCert;
  agent_sig: string;
  node_sig: string;
}

export type RevocationTarget = { card: number } | { ephemeral: string };
export type RevokedBy = "agent" | "operator";

export interface Revocation {
  agent_id: string;
  target: RevocationTarget;
  issued_at: number;
  by: RevokedBy;
  signer_pubkey: string;
  sig: string;
}

export type Outcome = "ok" | "not_found" | { rejected: string };

export interface Receipt {
  node_pubkey: string;
  request_hash: string;
  kind: string;
  timestamp: number;
  outcome: Outcome;
  response_hash: string;
  sig: string;
}

function filtersCbor(f: Filters): CborValue {
  return { geohash: f.geohash ?? null, days: f.days ?? null, langs: f.langs ?? [] };
}

function normFilters(f?: Filters): Filters {
  return { geohash: f?.geohash ?? null, days: f?.days ?? null, langs: f?.langs ?? [] };
}

export function operatorCertCbor(c: OperatorCert): CborValue {
  return { operator_pubkey: hexToBytes(c.operator_pubkey), node_pubkey: hexToBytes(c.node_pubkey), issued_at: c.issued_at, expires_at: c.expires_at, sig: hexToBytes(c.sig) };
}

function operatorCertUnsigned(c: OperatorCert): CborValue {
  return { operator_pubkey: hexToBytes(c.operator_pubkey), node_pubkey: hexToBytes(c.node_pubkey), issued_at: c.issued_at, expires_at: c.expires_at };
}

export function verifyOperatorCert(c: OperatorCert, now = nowSecs()): boolean {
  if (now >= c.expires_at) return false;
  return verify(hexToBytes(c.operator_pubkey), signingHash(DOMAIN.opcert, operatorCertUnsigned(c)), hexToBytes(c.sig));
}

// ---------------------------------------------------------------- Card

export function cardUnsigned(c: Omit<Card, "agent_sig" | "node_sig" | "last_seen">): CborValue {
  return {
    agent_id: c.agent_id,
    agent_pubkey: hexToBytes(c.agent_pubkey),
    version: c.version,
    endpoints: c.endpoints,
    traits: c.traits,
    filters: filtersCbor(c.filters),
    model: c.model,
    map_version: c.map_version,
    issued_at: c.issued_at,
    expires_at: c.expires_at,
    operator_cert: operatorCertCbor(c.operator_cert),
  };
}

export function cardAgentSigned(c: Omit<Card, "node_sig">): CborValue {
  return {
    agent_id: c.agent_id,
    agent_pubkey: hexToBytes(c.agent_pubkey),
    version: c.version,
    endpoints: c.endpoints,
    traits: c.traits,
    filters: filtersCbor(c.filters),
    model: c.model,
    map_version: c.map_version,
    issued_at: c.issued_at,
    last_seen: c.last_seen,
    expires_at: c.expires_at,
    operator_cert: operatorCertCbor(c.operator_cert),
    agent_sig: hexToBytes(c.agent_sig),
  };
}

export function cardCbor(c: Card): Uint8Array {
  return encode({ ...(cardAgentSigned(c) as Record<string, CborValue>), node_sig: hexToBytes(c.node_sig) });
}

export function cardUnsignedBytes(c: Card): Uint8Array {
  return encode(cardUnsigned(c));
}

export function cardAgentSigningHash(c: Omit<Card, "agent_sig" | "node_sig" | "last_seen">): Uint8Array {
  return signingHash(DOMAIN.card, cardUnsigned(c));
}

export function cardNodeSigningHash(c: Omit<Card, "node_sig">): Uint8Array {
  return signingHash(DOMAIN.nodeSig, cardAgentSigned(c));
}

export interface CardInput {
  traits: string[];
  endpoints?: string[];
  filters?: Filters;
  version: number;
  /** Lifetime in seconds, at most 90 days. */
  ttl?: number;
  model?: string;
  mapVersion?: number;
  issuedAt?: number;
}

/** Build and sign a card. `operatorCert` comes from the node (`GET /v1/status`). */
export function makeCard(agent: AgentKey, input: CardInput, operatorCert: OperatorCert): Card {
  const issued = input.issuedAt ?? nowSecs();
  const ttl = Math.min(input.ttl ?? CARD_MAX_TTL, CARD_MAX_TTL);
  const base = {
    agent_id: agent.agentId,
    agent_pubkey: agent.publicKeyHex,
    version: input.version,
    endpoints: input.endpoints ?? [],
    traits: input.traits,
    filters: normFilters(input.filters),
    model: input.model ?? MODEL_V1,
    map_version: input.mapVersion ?? 1,
    issued_at: issued,
    expires_at: issued + ttl,
    operator_cert: operatorCert,
  };
  const agent_sig = bytesToHex(agent.sign(cardAgentSigningHash(base)));
  return { ...base, last_seen: issued, agent_sig, node_sig: "00".repeat(64) };
}

export function verifyCard(c: Card): { agent: boolean; node: boolean } {
  const agent = c.agent_id === agentIdFromPubkey(hexToBytes(c.agent_pubkey)) && verify(hexToBytes(c.agent_pubkey), cardAgentSigningHash(c), hexToBytes(c.agent_sig));
  const node = verify(hexToBytes(c.operator_cert.node_pubkey), cardNodeSigningHash(c), hexToBytes(c.node_sig));
  return { agent, node };
}

// ---------------------------------------------------------------- Ephemeral

export function ephemeralUnsigned(e: Omit<Ephemeral, "agent_sig" | "node_sig">): CborValue {
  return {
    agent_id: e.agent_id,
    agent_pubkey: hexToBytes(e.agent_pubkey),
    ephemeral_id: hexToBytes(e.ephemeral_id),
    text: e.text,
    filters: filtersCbor(e.filters),
    valid_from: e.valid_from,
    valid_until: e.valid_until,
    operator_cert: operatorCertCbor(e.operator_cert),
  };
}

export function ephemeralCbor(e: Ephemeral): Uint8Array {
  return encode({ ...(ephemeralUnsigned(e) as Record<string, CborValue>), agent_sig: hexToBytes(e.agent_sig), node_sig: hexToBytes(e.node_sig) });
}

export interface EphemeralInput {
  text: string;
  validFrom: number;
  validUntil: number;
  filters?: Filters;
  id?: Uint8Array;
}

export function makeEphemeral(agent: AgentKey, input: EphemeralInput, operatorCert: OperatorCert): Ephemeral {
  if (input.validUntil - input.validFrom > EPHEMERAL_MAX_TTL) throw new Error("ephemeral window longer than 7 days");
  const base = {
    agent_id: agent.agentId,
    agent_pubkey: agent.publicKeyHex,
    ephemeral_id: bytesToHex(input.id ?? randomBytes(16)),
    text: input.text,
    filters: normFilters(input.filters),
    valid_from: input.validFrom,
    valid_until: input.validUntil,
    operator_cert: operatorCert,
  };
  const agent_sig = bytesToHex(agent.sign(signingHash(DOMAIN.ephemeral, ephemeralUnsigned(base))));
  return { ...base, agent_sig, node_sig: "00".repeat(64) };
}

// ---------------------------------------------------------------- Revocation

export function revocationUnsigned(r: Omit<Revocation, "sig">): CborValue {
  const target: CborValue = "card" in r.target ? { card: r.target.card } : { ephemeral: hexToBytes(r.target.ephemeral) };
  return { agent_id: r.agent_id, target, issued_at: r.issued_at, by: r.by, signer_pubkey: hexToBytes(r.signer_pubkey) };
}

export function revocationCbor(r: Revocation): Uint8Array {
  return encode({ ...(revocationUnsigned(r) as Record<string, CborValue>), sig: hexToBytes(r.sig) });
}

export function makeRevocation(agent: AgentKey, target: RevocationTarget, issuedAt = nowSecs()): Revocation {
  const base = { agent_id: agent.agentId, target, issued_at: issuedAt, by: "agent" as RevokedBy, signer_pubkey: agent.publicKeyHex };
  const sig = bytesToHex(agent.sign(signingHash(DOMAIN.revocation, revocationUnsigned(base))));
  return { ...base, sig };
}

export function verifyRevocation(r: Revocation): boolean {
  return verify(hexToBytes(r.signer_pubkey), signingHash(DOMAIN.revocation, revocationUnsigned(r)), hexToBytes(r.sig));
}

// ---------------------------------------------------------------- Receipt

export function receiptUnsigned(r: Omit<Receipt, "sig">): CborValue {
  const outcome: CborValue = typeof r.outcome === "string" ? r.outcome : { rejected: r.outcome.rejected };
  return { node_pubkey: hexToBytes(r.node_pubkey), request_hash: hexToBytes(r.request_hash), kind: r.kind, timestamp: r.timestamp, outcome, response_hash: hexToBytes(r.response_hash) };
}

export function receiptCbor(r: Receipt): Uint8Array {
  return encode({ ...(receiptUnsigned(r) as Record<string, CborValue>), sig: hexToBytes(r.sig) });
}

/** A guardian's receipt is proof: verify it before trusting an answer. */
export function verifyReceipt(r: Receipt): boolean {
  return verify(hexToBytes(r.node_pubkey), signingHash(DOMAIN.receipt, receiptUnsigned(r)), hexToBytes(r.sig));
}

export function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}
