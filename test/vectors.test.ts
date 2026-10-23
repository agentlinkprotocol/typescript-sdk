import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { AgentKey, bytesToHex, cardAgentSigningHash, cardCbor, cardNodeSigningHash, cardUnsignedBytes, ephemeralCbor, ephemeralUnsigned, encode, hexToBytes, operatorCertCbor, receiptCbor, receiptUnsigned, revocationCbor, revocationUnsigned, signingHash, DOMAIN, verifyCard, verifyReceipt, verifyRevocation, verifyOperatorCert, type Card, type Ephemeral, type Receipt, type Revocation } from "../src/index.js";

const v = JSON.parse(readFileSync(new URL("../test-vectors/v1.json", import.meta.url), "utf8"));

describe("test vectors v1 (shared with the Rust node)", () => {
  const agent = AgentKey.fromSeed(v.keys.agent_seed);
  const node = AgentKey.fromSeed(v.keys.node_seed);
  const operator = AgentKey.fromSeed(v.keys.operator_seed);

  it("derives the same keys and agent id", () => {
    expect(agent.publicKeyHex).toBe(v.keys.agent_pubkey);
    expect(node.publicKeyHex).toBe(v.keys.node_pubkey);
    expect(operator.publicKeyHex).toBe(v.keys.operator_pubkey);
    expect(agent.agentId).toBe(v.agent_id);
  });

  it("operator certificate", () => {
    const cert = { ...v.operator_cert.object, sig: v.operator_cert.sig };
    expect(bytesToHex(encode(operatorCertCbor(cert)))).toBe(v.operator_cert.cbor);
    expect(bytesToHex(signingHash(DOMAIN.opcert, { operator_pubkey: hexToBytes(cert.operator_pubkey), node_pubkey: hexToBytes(cert.node_pubkey), issued_at: cert.issued_at, expires_at: cert.expires_at }))).toBe(v.operator_cert.signing_hash);
    expect(bytesToHex(operator.sign(hexToBytes(v.operator_cert.signing_hash)))).toBe(v.operator_cert.sig);
    expect(verifyOperatorCert(cert, cert.issued_at + 1)).toBe(true);
  });

  it("card: canonical bytes, hashes, signatures", () => {
    const cert = { ...v.operator_cert.object, sig: v.operator_cert.sig };
    const card: Card = { ...v.card.object, operator_cert: cert, agent_sig: v.card.agent_sig, node_sig: v.card.node_sig };
    expect(bytesToHex(cardUnsignedBytes(card))).toBe(v.card.unsigned_cbor);
    expect(bytesToHex(cardAgentSigningHash(card))).toBe(v.card.agent_signing_hash);
    expect(bytesToHex(agent.sign(cardAgentSigningHash(card)))).toBe(v.card.agent_sig);
    expect(bytesToHex(cardNodeSigningHash(card))).toBe(v.card.node_signing_hash);
    expect(bytesToHex(node.sign(cardNodeSigningHash(card)))).toBe(v.card.node_sig);
    expect(bytesToHex(cardCbor(card))).toBe(v.card.cbor);
    expect(verifyCard(card)).toEqual({ agent: true, node: true });
    const tampered = { ...card, traits: ["Plumber", "Astronomy enthusiast"] };
    expect(verifyCard(tampered).agent).toBe(false);
  });

  it("ephemeral", () => {
    const cert = { ...v.operator_cert.object, sig: v.operator_cert.sig };
    const e: Ephemeral = { ...v.ephemeral.object, operator_cert: cert, agent_sig: v.ephemeral.agent_sig, node_sig: v.ephemeral.node_sig };
    expect(bytesToHex(encode(ephemeralUnsigned(e)))).toBe(v.ephemeral.unsigned_cbor);
    expect(bytesToHex(agent.sign(signingHash(DOMAIN.ephemeral, ephemeralUnsigned(e))))).toBe(v.ephemeral.agent_sig);
    expect(bytesToHex(ephemeralCbor(e))).toBe(v.ephemeral.cbor);
  });

  it("revocations by agent and by operator", () => {
    for (const name of ["revocation_by_agent", "revocation_by_operator"]) {
      const r: Revocation = { ...v[name].object, sig: v[name].sig };
      expect(bytesToHex(encode(revocationUnsigned(r)))).toBe(v[name].unsigned_cbor);
      expect(bytesToHex(signingHash(DOMAIN.revocation, revocationUnsigned(r)))).toBe(v[name].signing_hash);
      expect(bytesToHex(revocationCbor(r))).toBe(v[name].cbor);
      expect(verifyRevocation(r)).toBe(true);
    }
    expect(bytesToHex(agent.sign(hexToBytes(v.revocation_by_agent.signing_hash)))).toBe(v.revocation_by_agent.sig);
    expect(bytesToHex(operator.sign(hexToBytes(v.revocation_by_operator.signing_hash)))).toBe(v.revocation_by_operator.sig);
  });

  it("receipts (ok and rejected)", () => {
    for (const name of ["receipt_ok", "receipt_rejected"]) {
      const r: Receipt = { ...v[name].object, sig: v[name].sig };
      expect(bytesToHex(signingHash(DOMAIN.receipt, receiptUnsigned(r)))).toBe(v[name].signing_hash);
      expect(bytesToHex(receiptCbor(r))).toBe(v[name].cbor);
      expect(verifyReceipt(r)).toBe(true);
      expect(verifyReceipt({ ...r, timestamp: r.timestamp + 1 })).toBe(false);
    }
  });
});
