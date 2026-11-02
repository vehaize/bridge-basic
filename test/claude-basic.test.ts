/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 * Synthetic bindings only. No real client, account, or operator database.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { isDeepStrictEqual } from "node:util";
import { ItemLifecycle, LifecycleError } from "../src/item-lifecycle.ts";
import { oauthParticipant, PARTICIPANTS, type OAuthParticipant } from "../src/participants.ts";
import { routeRequest } from "../src/router.ts";
import { deliverWake } from "../src/wake.ts";
import type { BridgeEnv } from "../src/oauth-routes.ts";
import { SqliteD1, pinSqliteNow } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";

const ORIGIN = "https://bridge.example";
const RESOURCE = `${ORIGIN}/mcp`;
const OWNER = "2026-10-22T00:00:00.000Z";
const OPEN = { idempotency_key: "req_basic_001", kind: "task", title: "Synthetic task", body: "Bounded local work", scope: { allowed_sources: [], allowed_resources: [] } };
const databases: SqliteD1[] = [];
const fetches: string[] = [];
const sha = (value: string) => createHash("sha256").update(value).digest("hex");
const errorCode = (code: string) => (error: unknown) => error instanceof LifecycleError && error.code === code;

class MemoryKv {
  readonly records = new Map<string, { value: string; metadata?: unknown; expires?: number }>();
  writes = 0;
  async get(key: string, options?: { type?: string }): Promise<unknown> {
    const row = this.records.get(key);
    if (!row || (row.expires !== undefined && row.expires <= Date.now() / 1000)) return null;
    return options?.type === "json" ? JSON.parse(row.value) as unknown : row.value;
  }
  async put(key: string, value: string, options?: { expiration?: number; expirationTtl?: number; metadata?: unknown }): Promise<void> {
    this.writes += 1;
    this.records.set(key, { value, metadata: options?.metadata, expires: options?.expirationTtl === undefined ? options?.expiration : Date.now() / 1000 + options.expirationTtl });
  }
  async delete(key: string): Promise<void> { this.writes += 1; this.records.delete(key); }
  async list(options?: { prefix?: string }): Promise<unknown> {
    return { keys: [...this.records].filter(([key]) => key.startsWith(options?.prefix ?? "")).map(([name, row]) => ({ name, metadata: row.metadata })), list_complete: true, cursor: "" };
  }
}
function fixture() {
  const d1 = new SqliteD1(); databases.push(d1);
  const kv = new MemoryKv();
  d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run("synthetic-owner@example.invalid", OWNER);
  const env: BridgeEnv = { DB: d1.binding(), OAUTH_KV: kv as unknown as KVNamespace, BRIDGE_ORIGIN: ORIGIN, ...permissiveRateLimits() };
  return { d1, kv, env };
}
type Fixture = ReturnType<typeof fixture>;
function form(path: string, values: Record<string, string>) {
  return new Request(`${ORIGIN}${path}`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(values) });
}
function seedCode(f: Fixture, participant: OAuthParticipant, letter: string) {
  const code = letter.repeat(43);
  f.d1.sqlite.prepare("INSERT INTO connect_code VALUES (?, ?, ?, ?, NULL)").run(sha(code), participant, OWNER, new Date(Date.now() + 600_000).toISOString());
  return code;
}
function consent(participant: OAuthParticipant, code: string) {
  const client = oauthParticipant(participant)!;
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, values: { client_id: client.clientId, redirect_uri: client.redirectUri, response_type: "code", code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", resource: RESOURCE, state: "synthetic-state", scope: "notes read", connect_code: code } };
}
async function issue(f: Fixture, participant: OAuthParticipant, letter: string) {
  const c = consent(participant, seedCode(f, participant, letter));
  const first = await routeRequest(form("/authorize", c.values), f.env);
  assert.equal(first.status, 303);
  const location = first.headers.get("Location")!;
  const replay = await routeRequest(form("/authorize", c.values), f.env);
  assert.equal(replay.status, 303);
  assert.equal(replay.headers.get("Location"), location);
  assert.ok(location.startsWith(`${c.values.redirect_uri}?`));
  const exchange = await routeRequest(form("/token", { grant_type: "authorization_code", code: new URL(location).searchParams.get("code")!, client_id: c.values.client_id, redirect_uri: c.values.redirect_uri, code_verifier: c.verifier, resource: RESOURCE }), f.env);
  assert.equal(exchange.status, 200);
  const tokens = await exchange.json() as { access_token: string; refresh_token: string; expires_in: number };
  assert.equal(tokens.expires_in, 3600);
  assert.ok(tokens.access_token.startsWith(`${participant}:`));
  return tokens;
}
function mcp(access: string, method: string, params?: unknown) {
  return new Request(RESOURCE, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${access}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
}
async function ping(f: Fixture, access: string) { return routeRequest(mcp(access, "ping"), f.env); }
function refresh(f: Fixture, participant: OAuthParticipant, token: string) {
  return routeRequest(form("/token", {
    grant_type: "refresh_token", refresh_token: token,
    client_id: oauthParticipant(participant)!.clientId, resource: RESOURCE,
  }), f.env);
}
function storedState(f: Fixture) {
  return {
    kv: JSON.stringify([...f.kv.records]), kvWrites: f.kv.writes,
    credentials: f.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(),
    families: f.d1.sqlite.prepare("SELECT * FROM oauth_refresh_family ORDER BY id").all(),
    refreshHistory: f.d1.sqlite.prepare("SELECT * FROM oauth_refresh_token ORDER BY family_id, position").all(),
  };
}

function assertStoredState(f: Fixture, before: ReturnType<typeof storedState>): void {
  // Boolean comparison keeps synthetic token records and hashes out of failure reports.
  assert.equal(isDeepStrictEqual(storedState(f), before), true, "refusal preserves persisted grant and family state");
}

beforeEach(() => {
  mock.method(console, "log", () => {});
  mock.method(console, "error", () => {});
  mock.method(globalThis, "fetch", async (input: unknown) => {
    const url = input instanceof Request ? input.url : String(input);
    fetches.push(url);
    const client = [oauthParticipant("dot")!, oauthParticipant("claude")!].find((entry) => entry.clientId === url);
    assert.ok(client, "test attempted an unmocked external fetch");
    const grantTypes = ["authorization_code", "refresh_token", ...(client.participant === "claude" ? ["urn:ietf:params:oauth:grant-type:jwt-bearer"] : [])];
    return Response.json({ client_id: client.clientId, client_name: client.name, redirect_uris: [client.redirectUri], grant_types: grantTypes, response_types: ["code"], token_endpoint_auth_method: "none" }, { headers: { "Cache-Control": "no-store" } });
  });
});
afterEach(() => { for (const db of databases.splice(0)) db.sqlite.close(); fetches.length = 0; mock.restoreAll(); });

describe("three equal Basic participants", () => {
  for (const sender of PARTICIPANTS) for (const recipient of PARTICIPANTS.filter((entry) => entry !== sender)) {
    it(`isolates and completes ${sender} to ${recipient}`, async () => {
      const f = fixture(), service = new ItemLifecycle(f.env.DB);
      const third = PARTICIPANTS.find((entry) => entry !== sender && entry !== recipient)!;
      const opened = await service.openItem(sender, { ...OPEN, recipient });
      const args = { item_id: opened.item.id };
      assert.equal(opened.item.recipient, recipient);
      assert.equal((await service.listItems(third, { box: "inbox" })).items.length, 0);
      assert.equal((await service.listItems(third, { box: "sent" })).items.length, 0);
      await assert.rejects(service.getItem(third, args), errorCode("not_found"));
      for (const actor of [sender, third]) await assert.rejects(service.claimItem(actor, args), errorCode("not_permitted"));
      assert.equal((await service.getItem(recipient, args)).item.delivered_at === null, false);
      assert.equal((await service.claimItem(recipient, args)).execute, true);
      assert.equal((await service.claimItem(recipient, args)).execute, false);
      await assert.rejects(service.submitResult(third, { ...args, result: "Forged" }), errorCode("not_permitted"));
      await assert.rejects(service.submitResult(recipient, { ...args, result: "Bad citation", sources: ["https://example.com/source"] }), errorCode("citation_mismatch"));
      await service.submitResult(recipient, { ...args, result: "Local result" });
      for (const actor of [recipient, third]) {
        await assert.rejects(service.reviewResult(actor, { ...args, decision: "accept" }), errorCode("not_permitted"));
        await assert.rejects(service.cancelItem(actor, args), errorCode("not_permitted"));
      }
      const reviewed = await service.reviewResult(sender, { ...args, decision: "accept", checked: true, note: "Checked locally" });
      assert.equal(reviewed.item.result_label, "checked_by_requester");
      assert.equal((await service.claimItem(recipient, args)).execute, false);
      assert.equal((await service.openItem(sender, { ...OPEN, recipient })).replayed, true);
      await assert.rejects(service.openItem(sender, { ...OPEN, recipient: third }), errorCode("idempotency_conflict"));
    });
  }
  it("preserves legacy default routes and hashes, rejects self/unknown/ambiguous routes and true authority", async () => {
    const f = fixture(), service = new ItemLifecycle(f.env.DB);
    for (const sender of ["dot", "grok_bot"] as const) {
      const opened = await service.openItem(sender, OPEN);
      assert.equal(opened.item.recipient, sender === "dot" ? "grok_bot" : "dot");
      const expected = sha(JSON.stringify({ body: OPEN.body, deadline_minutes: 360, envelope_sha256: opened.item.envelope_sha256, kind: OPEN.kind, title: OPEN.title }));
      assert.equal(f.d1.sqlite.prepare("SELECT request_sha256 FROM item WHERE id = ?").get(opened.item.id)?.request_sha256, expected);
      assert.equal((await service.openItem(sender, { ...OPEN, recipient: opened.item.recipient })).replayed, true);
    }
    for (const recipient of [undefined, null, "claude", "unknown"]) await assert.rejects(service.openItem("claude", { ...OPEN, recipient }), errorCode("invalid_input"));
    await assert.rejects(service.openItem("claude", { ...OPEN, recipient: "dot", authority: { external_actions: true } }), errorCode("envelope_rejected"));
  });
  it("applies cancellation, expiry, and the no-wake contract to Claude", async () => {
    const f = fixture(); let now = Date.now(); pinSqliteNow(f.d1.sqlite, () => now);
    const service = new ItemLifecycle(f.env.DB, () => now);
    const cancelled = await service.openItem("claude", { ...OPEN, recipient: "dot" });
    await service.cancelItem("claude", { item_id: cancelled.item.id });
    assert.equal((await service.claimItem("dot", { item_id: cancelled.item.id })).execute, false);
    const expiring = await service.openItem("dot", { ...OPEN, recipient: "claude", deadline_minutes: 5 });
    now += 300_000;
    await assert.rejects(service.claimItem("claude", { item_id: expiring.item.id }), errorCode("deadline_passed"));
    const before = f.d1.prepared.length;
    await deliverWake(f.env, { type: "item.opened", itemId: expiring.item.id, participant: "claude", occurredAt: new Date(now).toISOString() });
    assert.equal(f.d1.prepared.length, before);
    assert.deepEqual(fetches, []);
  });
});

describe("participant-bound refresh with the pinned real provider", () => {
  for (const participant of ["dot", "claude"] as const) {
    const other = participant === "dot" ? "claude" : "dot";
    it(`refreshes an active ${participant} credential while live writes are disabled`, async () => {
      const f = fixture(), issued = await issue(f, participant, participant[0]);
      f.env.LIVE_ENABLED = "false";
      const response = await refresh(f, participant, issued.refresh_token);
      assert.equal(response.status, 200);
      const rotated = await response.json() as { access_token: string; refresh_token: string; scope: string };
      assert.notEqual(rotated.access_token, issued.access_token);
      assert.notEqual(rotated.refresh_token, issued.refresh_token);
      assert.equal(rotated.scope, "notes read");
      assert.equal((await ping(f, rotated.access_token)).status, 200);
    });

    const inactive: [string, (f: Fixture) => void][] = [
      ["revoked", (f) => {
        f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ? WHERE participant = ?").run(OWNER, participant);
      }],
      ["blank revocation", (f) => {
        f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = '' WHERE participant = ?").run(participant);
      }],
      ["missing credential", (f) => {
        // Synthetic corrupt-state fixture: preserve the orphaned family so the
        // authentication guard must refuse it rather than relying on the FK.
        f.d1.sqlite.exec("PRAGMA foreign_keys = OFF");
        f.d1.sqlite.prepare("DELETE FROM participant_credential WHERE participant = ?").run(participant);
        f.d1.sqlite.exec("PRAGMA foreign_keys = ON");
      }],
      ["credential rebound to the other participant", (f) => {
        f.d1.sqlite.prepare("UPDATE participant_credential SET participant = ? WHERE participant = ?").run(other, participant);
      }],
      ["missing owner", (f) => { f.d1.sqlite.exec("DELETE FROM owner_lock"); }],
      ["owner re-claimed with the same email", (f) => {
        f.d1.sqlite.exec("DELETE FROM owner_lock");
        f.d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')")
          .run("synthetic-owner@example.invalid", "2026-10-23T00:00:00.000Z");
      }],
    ];
    for (const [name, change] of inactive) {
      it(`refuses ${participant} refresh without persisted changes after ${name}`, async () => {
        const f = fixture(), issued = await issue(f, participant, participant[0]);
        change(f);
        const before = storedState(f);
        for (let attempt = 0; attempt < 2; attempt += 1) {
          const response = await refresh(f, participant, issued.refresh_token);
          assert.equal(response.status, 400);
          assert.deepEqual(await response.json(), { error: "invalid_grant" });
          assertStoredState(f, before);
        }
        assert.equal((await ping(f, issued.access_token)).status, 401);
      });
    }

    it(`temporarily pauses ${participant} without destroying its grant and resumes the same client after enable`, async () => {
      const f = fixture(), issued = await issue(f, participant, participant[0]);
      f.d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = ?").run(participant);
      const before = storedState(f);
      for (let attempt = 0; attempt < 2; attempt += 1) {
        for (const response of [await refresh(f, participant, issued.refresh_token), await ping(f, issued.access_token)]) {
          assert.equal(response.status, 503);
          assert.equal(response.headers.get("Retry-After"), "60");
          assert.equal(response.headers.get("Cache-Control"), "no-store");
          assert.equal(response.headers.get("WWW-Authenticate"), null);
          assert.deepEqual(await response.json(), { error: "unavailable" });
        }
        assertStoredState(f, before);
      }
      f.d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = ?").run(participant);
      assert.equal((await ping(f, issued.access_token)).status, 200);
      const resumed = await refresh(f, participant, issued.refresh_token);
      assert.equal(resumed.status, 200);
      const rotated = await resumed.json() as { access_token: string };
      assert.equal((await ping(f, rotated.access_token)).status, 200);
    });

    it(`refuses ${participant} refresh when the stored client is rebound to ${other}`, async () => {
      const f = fixture(), issued = await issue(f, participant, participant[0]);
      const [key, row] = [...f.kv.records].find(([key]) => key.startsWith(`grant:${participant}:`))!;
      const grant = JSON.parse(row.value) as Record<string, unknown>;
      grant.clientId = oauthParticipant(other)!.clientId;
      row.value = JSON.stringify(grant); f.kv.records.set(key, row);
      const before = storedState(f);
      const response = await refresh(f, other, issued.refresh_token);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { error: "invalid_grant" });
      assertStoredState(f, before);
    });

    it(`denies ${participant} refresh on D1 failure and permits retry after recovery`, async () => {
      const f = fixture(), issued = await issue(f, participant, participant[0]);
      const before = storedState(f);
      f.d1.failRead(new Error("synthetic D1 outage"));
      const response = await refresh(f, participant, issued.refresh_token);
      assert.equal(response.status, 500);
      assert.deepEqual(await response.json(), { error: "internal_error" });
      assertStoredState(f, before);
      const recovered = await refresh(f, participant, issued.refresh_token);
      assert.equal(recovered.status, 200);
      const tokens = await recovered.json() as { access_token: string };
      assert.equal((await ping(f, tokens.access_token)).status, 200);
    });
  }
});

describe("claude.ai OAuth with the pinned real provider", () => {
  it("advertises CIMD plus none and shows the fixed Claude identity on consent", async () => {
    const f = fixture();
    const metadata = await (await routeRequest(new Request(`${ORIGIN}/.well-known/oauth-authorization-server`), f.env)).json() as { client_id_metadata_document_supported: boolean; token_endpoint_auth_methods_supported: string[]; registration_endpoint?: string };
    assert.equal(metadata.client_id_metadata_document_supported, true);
    assert.ok(metadata.token_endpoint_auth_methods_supported.includes("none"));
    assert.equal(metadata.registration_endpoint, undefined);
    const c = consent("claude", "c".repeat(43));
    const query = new URLSearchParams(c.values); query.delete("connect_code");
    const page = await routeRequest(new Request(`${ORIGIN}/authorize?${query}`), f.env);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /claude\.ai will connect as Claude/);
    assert.match(page.headers.get("Content-Security-Policy")!, /https:\/\/claude\.ai/);
    assert.deepEqual(fetches, []);
  });
  it("rejects crossed clients, callbacks, and connect codes before any provider fetch or spend", async () => {
    const f = fixture(), dot = oauthParticipant("dot")!, claude = oauthParticipant("claude")!;
    const c = consent("claude", seedCode(f, "dot", "d"));
    for (const values of [c.values, { ...c.values, redirect_uri: dot.redirectUri }, { ...c.values, client_id: dot.clientId, redirect_uri: claude.redirectUri }, { ...c.values, client_id: "https://claude.ai/unknown" }]) {
      assert.equal((await routeRequest(form("/authorize", values), f.env)).status, 400);
    }
    assert.equal(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, null);
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n, 0);
    assert.deepEqual(fetches, []);
  });
  it("keeps reconnect, credential revocation and all seven tools isolated between Dot and Claude", async () => {
    const f = fixture(), dot = await issue(f, "dot", "d"), claude = await issue(f, "claude", "c");
    assert.equal((await ping(f, dot.access_token)).status, 200);
    assert.equal((await ping(f, claude.access_token)).status, 200);
    for (const tokens of [dot, claude]) {
      const response = await routeRequest(mcp(tokens.access_token, "tools/list"), f.env);
      const listed = await response.json() as { result: { tools: { name: string }[] } };
      assert.deepEqual(listed.result.tools.map((tool) => tool.name).sort(), ["cancel_item", "claim_item", "get_item", "list_items", "open_item", "review_result", "submit_result"]);
    }
    const replacement = await issue(f, "claude", "e");
    assert.equal((await ping(f, claude.access_token)).status, 401);
    assert.equal((await ping(f, replacement.access_token)).status, 200);
    assert.equal((await ping(f, dot.access_token)).status, 200);
    f.d1.sqlite.exec("UPDATE participant SET enabled = 0 WHERE id = 'claude'");
    assert.equal((await ping(f, replacement.access_token)).status, 503);
    assert.equal((await ping(f, dot.access_token)).status, 200);
  });
  it("rotates Claude refresh tokens, preserves exact scope, and rejects crossed refresh clients", async () => {
    const f = fixture(), tokens = await issue(f, "claude", "c");
    const client = oauthParticipant("claude")!;
    const params = { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.clientId, resource: RESOURCE };
    const narrow = await routeRequest(form("/token", { ...params, scope: "notes" }), f.env);
    assert.equal(narrow.status, 400); assert.deepEqual(await narrow.json(), { error: "invalid_scope" });
    assert.equal((await routeRequest(form("/token", { ...params, client_id: oauthParticipant("dot")!.clientId }), f.env)).status, 400);
    const response = await routeRequest(form("/token", params), f.env);
    assert.equal(response.status, 200);
    const rotated = await response.json() as { access_token: string; refresh_token: string };
    assert.notEqual(rotated.refresh_token, tokens.refresh_token);
    assert.equal((await ping(f, rotated.access_token)).status, 200);
  });
  it("derives the MCP sender from Claude's verified credential", async () => {
    const f = fixture(), tokens = await issue(f, "claude", "c");
    const call = (args: unknown) => routeRequest(mcp(tokens.access_token, "tools/call", { name: "open_item", arguments: args }), f.env);
    const opened = await (await call({ ...OPEN, recipient: "dot" })).json() as { result: { isError: boolean; structuredContent: { item: { sender: string; recipient: string } } } };
    assert.equal(opened.result.isError, false);
    assert.equal(opened.result.structuredContent.item.sender, "claude");
    assert.equal(opened.result.structuredContent.item.recipient, "dot");
    assert.match(await (await call({ ...OPEN, recipient: "dot", sender: "grok_bot" })).text(), /invalid_input/);
  });
  it("rejects a stored grant rebound to Dot and honors the live write switch for Claude", async () => {
    const f = fixture(), tokens = await issue(f, "claude", "c");
    f.env.LIVE_ENABLED = "false";
    const response = await routeRequest(mcp(tokens.access_token, "tools/call", { name: "open_item", arguments: { ...OPEN, recipient: "dot" } }), f.env);
    assert.match(await response.text(), /live_disabled/);
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM item").get()?.n, 0);
    const [key, row] = [...f.kv.records].find(([key]) => key.startsWith("grant:claude:"))!;
    const changed = JSON.parse(row.value) as Record<string, unknown>; changed.clientId = oauthParticipant("dot")!.clientId;
    row.value = JSON.stringify(changed); f.kv.records.set(key, row);
    assert.equal((await ping(f, tokens.access_token)).status, 401);
  });
});
