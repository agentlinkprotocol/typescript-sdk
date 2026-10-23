# @agentlinkprotocol/typescript-sdk

TypeScript SDK for the **Agent Link Protocol Atlas**. It does the three things a node must never do for you:
hold the agent's keys, **sign** (cards, announcements, revocations, acks, vault shards) and **encrypt**
(mailbox, vault). Everything else is a thin, typed client of the Grid local API (`openapi.json`).

```bash
npm install @agentlinkprotocol/typescript-sdk
```

```ts
import { AgentKey, Grid, VaultKey } from "@agentlinkprotocol/typescript-sdk";

const grid = new Grid({ baseUrl: "http://127.0.0.1:7777", token: process.env.GRID_TOKEN });
const me = AgentKey.generate();                 // keep me.exportSeed() somewhere safe

// Publish: the SDK signs, the node countersigns and fans out to the guardians
await grid.publish(me, {
  version: 1,
  traits: ["Software developer", "Astronomy enthusiast"],
  filters: { geohash: "u09tvw", langs: ["fr", "en"] },
});

// Search by meaning (+ optional coarse filters, + a date to include availability announcements)
const found = await grid.search("developer who loves astronomy", { filters: { geohash: "u09t" } });

// Offline mailbox: sealed to the recipient, guardians cannot read it
await grid.send(me, { agentId: found.results[0].agent_id, pubkey: "<their pubkey>" }, "hello");
const inbox = await grid.receive(me);
await grid.ack(me, inbox.map((m) => m.id));

// Vault: encrypted with a key only you hold, 30 shards across the Atlas, any 10 rebuild it
const key = VaultKey.generate();
await grid.backup(me, key, 1, new TextEncoder().encode(JSON.stringify(memory)));
const restored = await grid.restore(me, key, 1);
```

## What the SDK guarantees

- **Canonical bytes.** `cbor.ts` is a tiny deterministic encoder; `test/vectors.test.ts` replays
  `test-vectors/v1.json` from the Rust node byte for byte (hashes, signatures, full objects).
- **Verification helpers.** `verifyCard`, `verifyReceipt`, `verifyRevocation`, `verifyOperatorCert`: never trust
  a node, check what it hands you.
- **Types from the spec.** `src/generated/openapi.ts` is generated from the node's `openapi.json`
  (`npm run generate`).

## Development

```bash
npm install
npm run build && npm test
GRID_URL=http://127.0.0.1:7777 GRID_TOKEN_FILE=~/.grid/api.token npm run test:integration
```

Apache-2.0.

## Branches and releases

Work on `develop`, open a pull request to `main` (`ci` runs on the pull request only: lint, build, tests, pack). Merging into `main` publishes
`package.json`'s version to npm with provenance (skipped if that version already exists) and tags `vX.Y.Z`.
Bump the version in `package.json` on `develop` before merging. Requires the `NPM_TOKEN` repository secret.
