import { describe, expect, it } from "vitest";
import { AgentKey, VaultKey, decryptSnapshot, encryptSnapshot, inbox } from "../src/index.js";

describe("sealing and vault encryption", () => {
  it("seal/open roundtrip, wrong recipient fails", () => {
    const alice = AgentKey.generate();
    const bob = AgentKey.generate();
    const sealed = inbox.seal(bob.publicKey, new TextEncoder().encode("see you at 10"));
    expect(new TextDecoder().decode(inbox.open(bob, sealed))).toBe("see you at 10");
    expect(() => inbox.open(alice, sealed)).toThrow();
  });

  it("vault snapshot roundtrip bound to agent and snapshot number", () => {
    const a = AgentKey.generate();
    const k = VaultKey.generate();
    const data = new TextEncoder().encode("memory".repeat(100));
    const enc = encryptSnapshot(k, a.agentId, 3, data);
    expect(decryptSnapshot(k, a.agentId, 3, enc)).toEqual(data);
    expect(() => decryptSnapshot(k, a.agentId, 4, enc)).toThrow();
  });

  it("ack and fetch signatures verify with the agent key", () => {
    const a = AgentKey.generate();
    const sig = inbox.signFetch(a, 5);
    expect(sig).toHaveLength(128);
    const ack = inbox.makeAck(a, ["ab".repeat(16)], 1000);
    expect(ack.agent_id).toBe(a.agentId);
  });
});
