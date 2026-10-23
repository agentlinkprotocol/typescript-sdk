/**
 * Client of the Grid local API (http://127.0.0.1:7777). Thin: every call maps to one route of
 * `openapi.json`. Signing happens in this process (see `objects.ts`), never on the node.
 */
import type { paths } from "./generated/openapi.js";
import { bytesToHex, hexToBytes } from "./bytes.js";
import { AgentKey } from "./keys.js";
import { makeCard, makeEphemeral, makeRevocation, type Card, type CardInput, type EphemeralInput, type Filters, type OperatorCert, type Revocation, type RevocationTarget, nowSecs } from "./objects.js";
import { makeAck, open, seal, signFetch } from "./inbox.js";
import { decryptSnapshot, encryptSnapshot, signShards, VaultKey, type UnsignedShard } from "./vault.js";

type Json<P extends keyof paths, M extends keyof paths[P]> = paths[P][M] extends { responses: { 200: { content: { "application/json": infer R } } } } ? R : never;

export type NodeStatus = Json<"/v1/status", "get">;
export type PublishReport = Json<"/v1/cards", "post">;
export type SearchResult = Json<"/v1/search", "post">;
export type CardLookup = Json<"/v1/cards/{agent_id}", "get">;
export type AtlasStats = Json<"/v1/atlas/stats", "get">;
export type LedgerPage = Json<"/v1/ledger", "get">;
export type VaultGetReport = Json<"/v1/vault/{agent_id}/{snapshot}", "get">;
export type VaultPutReport = Json<"/v1/vault/{agent_id}", "put">;
export type FetchResponse = Json<"/v1/inbox/{agent_id}/fetch", "post">;
export type InboxMessage = FetchResponse["messages"][number];

export interface GridOptions {
  baseUrl?: string;
  token?: string;
  fetch?: typeof fetch;
}

export interface SearchOptions {
  filters?: Filters;
  /** Target date (unix seconds): includes availability announcements, disables caching. */
  at?: number;
  k?: number;
}

export class GridError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export class Grid {
  readonly baseUrl: string;
  private readonly token?: string;
  private readonly f: typeof fetch;
  private statusCache?: NodeStatus;

  constructor(opts: GridOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "http://127.0.0.1:7777").replace(/\/$/, "");
    this.token = opts.token;
    this.f = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await this.f(this.baseUrl + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    if (!res.ok) {
      let msg = text;
      try {
        msg = (JSON.parse(text) as { error?: string }).error ?? text;
      } catch {
        /* keep raw */
      }
      throw new GridError(res.status, msg);
    }
    return JSON.parse(text) as T;
  }

  // ---- node

  status(): Promise<NodeStatus> {
    return this.call("GET", "/v1/status");
  }

  /** The node's operator certificate, cached; every card carries it. */
  async operatorCert(): Promise<OperatorCert> {
    this.statusCache ??= await this.status();
    return this.statusCache.operator_cert as OperatorCert;
  }

  atlasStats(): Promise<AtlasStats> {
    return this.call("GET", "/v1/atlas/stats");
  }

  ledger(from = 0, limit = 100): Promise<LedgerPage> {
    return this.call("GET", `/v1/ledger?from=${from}&limit=${limit}`);
  }

  // ---- cards

  /** Build, sign and publish a card. The node fills `last_seen` and countersigns. */
  async publish(agent: AgentKey, input: CardInput): Promise<PublishReport> {
    const status = await this.status();
    this.statusCache = status;
    const card = makeCard(agent, { ...input, model: input.model ?? status.model, mapVersion: input.mapVersion ?? status.map_version }, status.operator_cert as OperatorCert);
    return this.publishSigned(card);
  }

  publishSigned(card: Card): Promise<PublishReport> {
    return this.call("POST", "/v1/cards", card);
  }

  getCard(agentId: string): Promise<CardLookup> {
    return this.call("GET", `/v1/cards/${encodeURIComponent(agentId)}`);
  }

  async announce(agent: AgentKey, input: EphemeralInput): Promise<PublishReport> {
    const cert = await this.operatorCert();
    return this.call("POST", "/v1/ephemerals", makeEphemeral(agent, input, cert));
  }

  revoke(agent: AgentKey, target: RevocationTarget): Promise<PublishReport> {
    return this.call("POST", "/v1/revocations", makeRevocation(agent, target));
  }

  revokeSigned(r: Revocation): Promise<PublishReport> {
    return this.call("POST", "/v1/revocations", r);
  }

  // ---- search

  search(text: string, opts: SearchOptions = {}): Promise<SearchResult> {
    return this.call("POST", "/v1/search", { text, filters: opts.filters ?? {}, at: opts.at ?? null, k: opts.k ?? null });
  }

  searchVector(vector: number[], opts: SearchOptions = {}): Promise<SearchResult> {
    return this.call("POST", "/v1/search", { vector, filters: opts.filters ?? {}, at: opts.at ?? null, k: opts.k ?? null });
  }

  async embed(texts: string[]): Promise<{ model: string; vectors: number[][] }> {
    return this.call("POST", "/v1/embed", { texts });
  }

  // ---- inbox

  /** Seal `plaintext` to a recipient and deposit it in their mailbox. */
  async send(from: AgentKey, to: { agentId: string; pubkey: string }, plaintext: Uint8Array | string): Promise<Json<"/v1/inbox", "post">> {
    const bytes = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
    const sealed = seal(hexToBytes(to.pubkey), bytes);
    return this.call("POST", "/v1/inbox", { to: to.agentId, from_pubkey: from.publicKeyHex, sealed: bytesToHex(sealed) });
  }

  /** Fetch and open pending messages. Call `ack` once they are processed. */
  async receive(agent: AgentKey): Promise<Array<{ id: string; from: string; depositedAt: number; plaintext: Uint8Array }>> {
    const nonce = nowSecs();
    const res: FetchResponse = await this.call("POST", `/v1/inbox/${agent.agentId}/fetch`, { agent_pubkey: agent.publicKeyHex, nonce, auth: signFetch(agent, nonce) });
    const out = [];
    for (const m of res.messages) {
      try {
        out.push({ id: m.message_id, from: m.from_pubkey, depositedAt: m.deposited_at, plaintext: open(agent, hexToBytes(m.ciphertext)) });
      } catch {
        /* undecryptable message: skip, it was not for us */
      }
    }
    return out;
  }

  ack(agent: AgentKey, messageIds: string[]): Promise<{ removed_copies: number }> {
    return this.call("POST", `/v1/inbox/${agent.agentId}/ack`, makeAck(agent, messageIds, nowSecs()));
  }

  // ---- vault

  /** Encrypt, split and store a snapshot. Returns how many of the 30 shards were stored. */
  async backup(agent: AgentKey, key: VaultKey, snapshot: number, data: Uint8Array, ttlSecs = 365 * 86_400): Promise<VaultPutReport> {
    const encrypted = encryptSnapshot(key, agent.agentId, snapshot, data);
    const { shards } = await this.call<{ shards: UnsignedShard[] }>("POST", "/v1/vault/shards", { encrypted: bytesToHex(encrypted) });
    const cert = await this.operatorCert();
    const signed = signShards(agent, shards, snapshot, nowSecs() + ttlSecs, cert);
    return this.call("PUT", `/v1/vault/${agent.agentId}`, { shards: signed });
  }

  /** Collect shards, rebuild and decrypt a snapshot. */
  async restore(agent: AgentKey, key: VaultKey, snapshot: number): Promise<Uint8Array> {
    const r: VaultGetReport = await this.call("GET", `/v1/vault/${agent.agentId}/${snapshot}`);
    if (!r.encrypted) throw new GridError(404, `only ${r.shards_found} shards found, cannot rebuild snapshot ${snapshot}`);
    return decryptSnapshot(key, agent.agentId, snapshot, hexToBytes(r.encrypted));
  }
}
