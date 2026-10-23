/** Runs against a live node: GRID_URL and GRID_TOKEN (or <data_dir>/api.token). */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { AgentKey, Grid, VaultKey, verifyCard } from "../src/index.js";

const url = process.env.GRID_URL ?? "http://127.0.0.1:7777";
const token = process.env.GRID_TOKEN ?? (process.env.GRID_TOKEN_FILE ? readFileSync(process.env.GRID_TOKEN_FILE, "utf8").trim() : undefined);

describe("live node", () => {
  const grid = new Grid({ baseUrl: url, token });

  it("publishes, searches, messages and backs up", async () => {
    const status = await grid.status();
    expect(status.node_pubkey).toHaveLength(64);

    const alice = AgentKey.generate();
    const bob = AgentKey.generate();
    const r = await grid.publish(alice, { version: 1, traits: ["Software developer", "Astronomy enthusiast"], filters: { geohash: "u09tvw", langs: ["fr", "en"] } });
    expect(r.card_copies).toBeGreaterThan(0);
    await grid.publish(bob, { version: 1, traits: ["Professional hairdresser near République"] });

    const found = await grid.search("software developer astronomy", { k: 20 });
    expect(found.results.map((x) => x.agent_id)).toContain(alice.agentId);
    const near = await grid.search("hairdresser", { filters: { geohash: "u09t" } });
    expect(near.results.every((x) => x.agent_id !== bob.agentId)).toBe(true); // bob has no geohash

    const lookup = await grid.getCard(alice.agentId);
    expect(lookup.card && verifyCard(lookup.card as never)).toEqual({ agent: true, node: true });

    await grid.send(alice, { agentId: bob.agentId, pubkey: bob.publicKeyHex }, "appointment confirmed 10:00");
    const msgs = await grid.receive(bob);
    expect(msgs.map((m) => new TextDecoder().decode(m.plaintext))).toContain("appointment confirmed 10:00");
    await grid.ack(bob, msgs.map((m) => m.id));
    expect(await grid.receive(bob)).toHaveLength(0);

    const key = VaultKey.generate();
    const memory = new TextEncoder().encode(JSON.stringify({ likes: "astronomy" }));
    const put = await grid.backup(alice, key, 1, memory);
    expect(put.shards_stored).toBe(30);
    expect(await grid.restore(alice, key, 1)).toEqual(memory);

    await grid.revoke(alice, { card: 1 });
    const after = await grid.search("software developer astronomy", { at: Math.floor(Date.now() / 1000) + 1, k: 50 });
    expect(after.results.every((x) => x.agent_id !== alice.agentId)).toBe(true);
  });
});
