/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { afterEach, describe, it, mock } from "node:test";
import { CHATGPT_CLIENT_ID, CHATGPT_REDIRECT, type BridgeEnv } from "../src/oauth-routes.ts";
import { mcpChallenge } from "../src/mcp-route.ts";
import { routeRequest } from "../src/router.ts";
import { SqliteD1 } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";

const ORIGIN = "https://bridge.example";
const RESOURCE = `${ORIGIN}/mcp`;
const EMAIL = "synthetic-owner@example.invalid";
const OWNER = "2026-10-22T00:00:00.000Z";
const CODE = "c".repeat(43);
const HASH = createHash("sha256").update(CODE).digest("hex");
const GROK = `admrn_gb_${"a".repeat(43)}`;
const GROK_HASH = createHash("sha256").update(GROK).digest("hex");
const CHALLENGE = mcpChallenge(ORIGIN);
const CIMD = {
  client_id: CHATGPT_CLIENT_ID,
  client_name: "ChatGPT",
  redirect_uris: [CHATGPT_REDIRECT],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
};

interface Stored {
  value: string;
  metadata?: unknown;
  expiresAt?: number;
}

class MemoryKv {
  readonly records = new Map<string, Stored>();

  async get(key: string, options?: { type?: string }): Promise<unknown> {
    const row = this.records.get(key);
    if (!row || (row.expiresAt !== undefined && row.expiresAt <= Date.now() / 1000)) return null;
    return options?.type === "json" ? JSON.parse(row.value) as unknown : row.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number; metadata?: unknown }): Promise<void> {
    const expiresAt = options?.expirationTtl === undefined ? undefined : Math.floor(Date.now() / 1000) + options.expirationTtl;
    this.records.set(key, { value, metadata: options?.metadata, expiresAt });
  }

  async delete(key: string): Promise<void> {
    this.records.delete(key);
  }

  async list(options?: { prefix?: string; limit?: number; cursor?: string }): Promise<{
    keys: { name: string; metadata?: unknown }[];
    list_complete: boolean;
    cursor: string;
  }> {
    const names = [...this.records.keys()].filter((name) => name.startsWith(options?.prefix ?? "")).sort();
    const start = options?.cursor ? Number(options.cursor) : 0;
    const slice = names.slice(start, start + (options?.limit ?? names.length));
    return {
      keys: slice.map((name) => ({ name, metadata: this.records.get(name)?.metadata })),
      list_complete: start + slice.length >= names.length,
      cursor: String(start + slice.length),
    };
  }
}

const databases: SqliteD1[] = [];
const logs: string[] = [];

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

function fresh(): { d1: SqliteD1; kv: MemoryKv; env: BridgeEnv } {
  const d1 = new SqliteD1();
  databases.push(d1);
  const kv = new MemoryKv();
  const expires = new Date(Date.now() + 600_000).toISOString();
  d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run(EMAIL, OWNER);
  d1.sqlite.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, ?, NULL)").run(HASH, OWNER, expires);
  d1.sqlite.prepare(`INSERT INTO participant_credential
    (id, participant, kind, token_sha256, owner_claimed_at, created_at)
    VALUES ('credential_grok', 'grok_bot', 'bearer', ?, ?, ?)`).run(GROK_HASH, OWNER, OWNER);
  return {
    d1,
    kv,
    env: { DB: d1.binding(), OAUTH_KV: kv as unknown as KVNamespace, BRIDGE_ORIGIN: ORIGIN, OWNER_EMAIL: EMAIL, ...permissiveRateLimits() },
  };
}

function form(challenge: string, scope?: string): string {
  const params = new URLSearchParams({
    connect_code: CODE,
    client_id: CHATGPT_CLIENT_ID,
    redirect_uri: CHATGPT_REDIRECT,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
    state: "synthetic-state",
  });
  if (scope !== undefined) params.set("scope", scope);
  return params.toString();
}

function postForm(url: string, body: string): Request {
  return new Request(url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
}

async function issue(env: BridgeEnv, scope?: string): Promise<string> {
  const { verifier, challenge } = pkce();
  const consented = await routeRequest(postForm(`${ORIGIN}/authorize`, form(challenge, scope)), env);
  assert.equal(consented.status, 303, scope ?? "empty-scope");
  const code = new URL(consented.headers.get("Location") ?? "").searchParams.get("code");
  assert.ok(code);
  const token = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: CHATGPT_REDIRECT,
    client_id: CHATGPT_CLIENT_ID,
    code_verifier: verifier,
    resource: RESOURCE,
  }).toString()), env);
  assert.equal(token.status, 200);
  const body = await token.json() as { access_token?: string };
  assert.equal(typeof body.access_token, "string");
  return body.access_token ?? "";
}

function mcp(token: string | null, message: unknown, headers: HeadersInit = {}): Request {
  const requestHeaders = new Headers({ "Content-Type": "application/json", ...Object.fromEntries(new Headers(headers)) });
  if (token !== null) requestHeaders.set("Authorization", `Bearer ${token}`);
  return new Request(`${ORIGIN}/mcp`, { method: "POST", headers: requestHeaders, body: JSON.stringify(message) });
}

function rpc(method: string, params?: unknown): unknown {
  return { jsonrpc: "2.0", id: 1, method, ...(params === undefined ? {} : { params }) };
}

function installFetch(): void {
  mock.method(globalThis, "fetch", async (input: unknown) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== CHATGPT_CLIENT_ID) throw new Error("unexpected fetch");
    return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
  });
}

function captureLogs(): void {
  mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
  mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
}

async function unauthorized(response: Response, status: 401 | 403 = 401, scope?: string): Promise<void> {
  assert.equal(response.status, status);
  assert.deepEqual(await response.json(), { error: "unauthorized" });
  const challenge = status === 403
    ? `${CHALLENGE}, error="insufficient_scope", scope="${scope ?? ""}"`
    : CHALLENGE;
  assert.equal(response.headers.get("WWW-Authenticate"), challenge);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
}

function clean(value: string, secrets: string[]): void {
  for (const secret of secrets) assert.equal(value.includes(secret), false);
}

function grantRecord(kv: MemoryKv): { key: string; value: Record<string, unknown> } {
  const grants = [...kv.records.entries()].filter(([key]) => key.startsWith("grant:"));
  assert.equal(grants.length, 1);
  const [key, row] = grants[0] ?? [];
  assert.equal(typeof key, "string");
  return { key: key ?? "", value: JSON.parse(row?.value ?? "{}") as Record<string, unknown> };
}

const TOOLS = ["list_items", "get_item", "open_item", "claim_item", "submit_result", "review_result", "cancel_item"];
const CLOSED_CALL = {
  idempotency_key: "req_closed_01", kind: "task", title: "Closed", body: "Must not run.",
  item_id: "item_00000000-0000-4000-8000-000000000000",
};

afterEach(() => {
  for (const db of databases.splice(0)) db.sqlite.close();
  logs.length = 0;
  mock.restoreAll();
});

describe("production /mcp", () => {
  it("checks method, size, media type, and protocol before any credential read", async () => {
    const { d1, env } = fresh();
    for (const method of ["GET", "DELETE"]) {
      const response = await routeRequest(new Request(`${ORIGIN}/mcp`, {
        method,
        headers: { Authorization: `Bearer ${GROK}` },
      }), env);
      assert.equal(response.status, 405, method);
      assert.equal(response.headers.get("Allow"), "POST");
      assert.equal(response.headers.get("WWW-Authenticate"), null);
    }
    const oversize = await routeRequest(new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: { Authorization: `Bearer ${GROK}`, "Content-Type": "application/json" },
      body: "x".repeat(16 * 1024 + 1),
    }), env);
    assert.equal(oversize.status, 413);
    const media = await routeRequest(new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: { Authorization: `Bearer ${GROK}`, "Content-Type": "text/plain" },
      body: "{}",
    }), env);
    assert.equal(media.status, 415);
    const version = await routeRequest(mcp(GROK, rpc("ping"), { "MCP-Protocol-Version": "2025-11-25" }), env);
    assert.equal(version.status, 400);
    assert.equal(d1.sessions.length, 0);
    assert.equal(d1.writeBatches, 0);
    captureLogs();
    const logged = await routeRequest(new Request(`${ORIGIN}/mcp`, { method: "GET" }), env);
    assert.equal(logged.status, 405);
    const refusal = logs.join("\n");
    assert.match(refusal, /"event":"mcp.refused"/);
    assert.match(refusal, /"reason":"method_not_allowed"/);
    clean(refusal, [GROK, GROK_HASH, EMAIL, CODE]);
  });

  it("fails closed on a missing, malformed, revoked or stale Grok credential and temporarily pauses disabled Grok", async () => {
    captureLogs();
    const missing = fresh();
    const absent = await routeRequest(mcp(null, rpc("ping")), missing.env);
    await unauthorized(absent);
    assert.equal(missing.d1.sessions.length, 0);
    assert.match(logs.join("\n"), /"reason":"missing_token"/);

    const { d1, env } = fresh();
    logs.length = 0;
    const bad = await routeRequest(mcp("not-a-token", rpc("tools/call", { name: "open_item", arguments: { title: "hidden" } })), env);
    await unauthorized(bad);
    assert.equal(d1.sessions.length, 0);
    const prefixed = await routeRequest(mcp(`admrn_gb_${"z".repeat(10)}`, rpc("ping")), env);
    await unauthorized(prefixed);
    assert.equal(d1.sessions.length, 0);

    const query = new Request(`${ORIGIN}/mcp?access_token=${GROK}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...rpc("ping") as object, access_token: GROK }),
    });
    await unauthorized(await routeRequest(query, env));
    assert.equal(d1.sessions.length, 0);

    const ok = await routeRequest(mcp(GROK, rpc("ping")), env);
    assert.equal(ok.status, 200);
    d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ? WHERE id = 'credential_grok'").run(OWNER);
    await unauthorized(await routeRequest(mcp(GROK, rpc("ping")), env));
    d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = NULL WHERE id = 'credential_grok'").run();
    d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'grok_bot'").run();
    const paused = await routeRequest(mcp(GROK, rpc("ping")), env);
    assert.equal(paused.status, 503);
    assert.equal(paused.headers.get("Retry-After"), "60");
    assert.deepEqual(await paused.json(), { error: "unavailable" });
    d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = 'grok_bot'").run();
    assert.equal((await routeRequest(mcp(GROK, rpc("ping")), env)).status, 200);
    d1.sqlite.prepare("UPDATE owner_lock SET claimed_at = ?").run("1999-01-01T00:00:00.000Z");
    await unauthorized(await routeRequest(mcp(GROK, rpc("ping")), env));
    clean(logs.join("\n"), [GROK, GROK_HASH, EMAIL, CODE]);
  });

  it("lets Grok and Dot exchange an item", async () => {
    installFetch();
    captureLogs();
    const { d1, kv, env } = fresh();
    const access = await issue(env);
    const opened = await routeRequest(mcp(access, rpc("tools/call", {
      name: "open_item",
      arguments: {
        idempotency_key: "req_route_0001", kind: "task", title: "Route title", body: "Route body",
        scope: { allowed_sources: [], allowed_resources: [] },
      },
    })), env);
    assert.equal(opened.status, 200);
    const openedBody = await opened.json() as { result: { structuredContent: { item: { id: string; sender: string }; replayed: boolean } } };
    assert.equal(openedBody.result.structuredContent.item.sender, "dot");
    assert.equal(openedBody.result.structuredContent.replayed, false);
    const listed = await routeRequest(mcp(GROK, rpc("tools/call", {
      name: "list_items",
      arguments: { box: "inbox" },
    })), env);
    assert.equal(listed.status, 200);
    const listedBody = await listed.json() as { result: { structuredContent: { items: { id: string }[] } } };
    assert.equal(listedBody.result.structuredContent.items[0]?.id, openedBody.result.structuredContent.item.id);

    d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ? WHERE participant = 'dot'").run(OWNER);
    await unauthorized(await routeRequest(mcp(access, rpc("ping")), env));

    const audience = fresh();
    const audienceToken = await issue(audience.env);
    for (const row of audience.kv.records.values()) {
      if (!row.value.includes("\"audience\"")) continue;
      const data = JSON.parse(row.value) as { audience?: string };
      if (data.audience === RESOURCE) data.audience = "https://other.example/mcp";
      row.value = JSON.stringify(data);
    }
    await unauthorized(await routeRequest(mcp(audienceToken, rpc("ping")), audience.env));

    const client = fresh();
    const clientToken = await issue(client.env);
    let changedClient = false;
    for (const row of client.kv.records.values()) {
      let data: { clientId?: string; grant?: { clientId?: string } };
      try {
        data = JSON.parse(row.value) as { clientId?: string; grant?: { clientId?: string } };
      } catch {
        continue;
      }
      let changed = false;
      if (data.clientId === CHATGPT_CLIENT_ID) {
        data.clientId = "https://evil.example/client.json";
        changed = true;
      }
      if (data.grant?.clientId === CHATGPT_CLIENT_ID) {
        data.grant.clientId = "https://evil.example/client.json";
        changed = true;
      }
      if (!changed) continue;
      row.value = JSON.stringify(data);
      changedClient = true;
    }
    assert.equal(changedClient, true);
    await unauthorized(await routeRequest(mcp(clientToken, rpc("ping")), client.env));

    const expired = fresh();
    const expiredToken = await issue(expired.env);
    let changedExpiry = false;
    for (const row of expired.kv.records.values()) {
      const data = JSON.parse(row.value) as { expiresAt?: number };
      if (typeof data.expiresAt === "number") {
        data.expiresAt = Math.floor(Date.now() / 1000) - 5;
        row.value = JSON.stringify(data);
        changedExpiry = true;
      }
    }
    assert.equal(changedExpiry, true);
    await unauthorized(await routeRequest(mcp(expiredToken, rpc("ping")), expired.env));
    clean(`${logs.join("\n")}\n${JSON.stringify(openedBody)}`, [access, audienceToken, clientToken, expiredToken, GROK, GROK_HASH, EMAIL, CODE]);
    assert.equal(kv.records.size > 0, true);
  });

  it("accepts a Bridge-issued Dot scope and rejects a different or forged one", async () => {
    installFetch();
    captureLogs();
    const empty = fresh();
    const emptyToken = await issue(empty.env);
    assert.equal((await routeRequest(mcp(emptyToken, rpc("ping")), empty.env)).status, 200);

    const scoped = fresh();
    const scopedToken = await issue(scoped.env, "notes");
    const grants = [...scoped.kv.records.entries()].filter(([key]) => key.startsWith("grant:"));
    assert.equal(grants.length, 1);
    assert.deepEqual(JSON.parse(grants[0]?.[1].value ?? "{}").scope, ["notes"]);
    const opened = await routeRequest(mcp(scopedToken, rpc("tools/call", {
      name: "open_item",
      arguments: {
        idempotency_key: "req_scope_0001", kind: "task", title: "Scoped title", body: "Scoped body",
        scope: { allowed_sources: [], allowed_resources: [] },
      },
    })), scoped.env);
    assert.equal(opened.status, 200);
    const openedBody = await opened.json() as { result: { structuredContent: { item: { id: string; sender: string } } } };
    assert.equal(openedBody.result.structuredContent.item.sender, "dot");
    const claimed = await routeRequest(mcp(scopedToken, rpc("tools/call", {
      name: "claim_item",
      arguments: { item_id: openedBody.result.structuredContent.item.id },
    })), scoped.env);
    assert.equal(claimed.status, 200);
    const claimedBody = await claimed.json() as { result: { structuredContent: { error?: string } } };
    assert.equal(claimedBody.result.structuredContent.error, "not_permitted");

    let changed = 0;
    for (const [key, row] of scoped.kv.records) {
      if (!key.startsWith("token:")) continue;
      const data = JSON.parse(row.value) as { scope?: string[]; grant?: { scope?: string[] } };
      if (Array.isArray(data.scope)) data.scope = ["other"];
      if (Array.isArray(data.grant?.scope)) data.grant.scope = ["other"];
      row.value = JSON.stringify(data);
      changed += 1;
    }
    assert.equal(changed > 0, true);
    const before = scoped.d1.writeBatches;
    const refused = await routeRequest(mcp(scopedToken, rpc("tools/call", {
      name: "open_item",
      arguments: { idempotency_key: "req_scope_0002", kind: "task", title: "Other title", body: "Other body" },
    })), scoped.env);
    await unauthorized(refused, 403, "notes");
    assert.equal((refused.headers.get("WWW-Authenticate") ?? "").includes("other"), false);
    assert.equal(scoped.d1.writeBatches, before);
    assert.equal(scoped.d1.sqlite.prepare("SELECT COUNT(*) AS count FROM item").get()?.count, 1);
    assert.match(logs.join("\n"), /"reason":"insufficient_scope"/);

    const forged = `dot:${"f".repeat(16)}:${"s".repeat(32)}`;
    await unauthorized(await routeRequest(mcp(forged, rpc("ping")), scoped.env));
    clean(`${logs.join("\n")}\n${JSON.stringify(openedBody)}`, [emptyToken, scopedToken, forged, GROK, GROK_HASH, EMAIL, CODE]);
  });

  it("binds a token to its exact grant and that grant's client", async () => {
    installFetch();
    captureLogs();
    const moved = fresh();
    const movedToken = await issue(moved.env);
    const grantId = movedToken.split(":")[1] ?? "";
    const current = grantRecord(moved.kv);
    assert.equal(current.key, `grant:dot:${grantId}`);
    assert.equal(current.value.id, grantId);
    assert.equal(current.value.clientId, CHATGPT_CLIENT_ID);
    moved.kv.records.delete(current.key);
    const otherGrant = "b".repeat(16);
    moved.kv.records.set(`grant:dot:${otherGrant}`, { value: JSON.stringify({ ...current.value, id: otherGrant }) });
    const movedWrites = moved.d1.writeBatches;
    await unauthorized(await routeRequest(mcp(movedToken, rpc("tools/call", {
      name: "open_item", arguments: { ...CLOSED_CALL, idempotency_key: "req_other_grant1" },
    })), moved.env));
    assert.equal(moved.d1.writeBatches, movedWrites);
    assert.equal(moved.d1.sqlite.prepare("SELECT COUNT(*) AS count FROM item").get()?.count, 0);

    const otherClient = fresh();
    const clientToken = await issue(otherClient.env);
    const clientGrant = grantRecord(otherClient.kv);
    clientGrant.value.clientId = "https://other.invalid/client.json";
    const storedClient = otherClient.kv.records.get(clientGrant.key);
    assert.ok(storedClient);
    storedClient.value = JSON.stringify(clientGrant.value);
    await unauthorized(await routeRequest(mcp(clientToken, rpc("ping")), otherClient.env));

    const otherId = fresh();
    const idToken = await issue(otherId.env);
    const idGrant = grantRecord(otherId.kv);
    idGrant.value.id = "c".repeat(16);
    const storedId = otherId.kv.records.get(idGrant.key);
    assert.ok(storedId);
    storedId.value = JSON.stringify(idGrant.value);
    await unauthorized(await routeRequest(mcp(idToken, rpc("ping")), otherId.env));
    clean(logs.join("\n"), [movedToken, clientToken, idToken, GROK, GROK_HASH, EMAIL, CODE]);
  });

  it("fails closed for a malformed scope, an unknown scope, a KV outage, a revoked grant, and a stale grant", async () => {
    installFetch();
    captureLogs();
    const dispatches = [
      rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "synthetic", version: "0" } }),
      rpc("ping"),
      rpc("tools/list"),
      { jsonrpc: "2.0", method: "notifications/initialized" },
      ...TOOLS.map((name) => rpc("tools/call", { name, arguments: CLOSED_CALL })),
    ];

    const unknown = fresh();
    const unknownToken = await issue(unknown.env, "notes");
    for (const [key, row] of unknown.kv.records) {
      if (!key.startsWith("token:")) continue;
      const data = JSON.parse(row.value) as { scope?: unknown; grant?: { scope?: unknown } };
      data.scope = ["unknown"];
      if (data.grant) data.grant.scope = ["unknown"];
      row.value = JSON.stringify(data);
    }
    const unknownWrites = unknown.d1.writeBatches;
    for (const message of dispatches) await unauthorized(await routeRequest(mcp(unknownToken, message), unknown.env), 403, "notes");
    assert.equal(unknown.d1.writeBatches, unknownWrites);
    assert.equal(unknown.d1.sqlite.prepare("SELECT COUNT(*) AS count FROM item").get()?.count, 0);
    assert.match(logs.join("\n"), /"reason":"insufficient_scope"/);

    const malformedGrant = fresh();
    const malformedGrantToken = await issue(malformedGrant.env, "notes");
    const malformed = grantRecord(malformedGrant.kv);
    malformed.value.scope = "notes";
    const storedMalformed = malformedGrant.kv.records.get(malformed.key);
    assert.ok(storedMalformed);
    storedMalformed.value = JSON.stringify(malformed.value);
    const malformedWrites = malformedGrant.d1.writeBatches;
    await unauthorized(await routeRequest(mcp(malformedGrantToken, rpc("tools/call", {
      name: "open_item", arguments: { ...CLOSED_CALL, idempotency_key: "req_bad_grant_scope" },
    })), malformedGrant.env));
    assert.equal(malformedGrant.d1.writeBatches, malformedWrites);

    const malformedTokenEnv = fresh();
    const malformedToken = await issue(malformedTokenEnv.env);
    const sessionsBefore = malformedTokenEnv.d1.sessions.length;
    for (const [key, row] of malformedTokenEnv.kv.records) {
      if (!key.startsWith("token:")) continue;
      const data = JSON.parse(row.value) as { scope?: unknown; grant?: { scope?: unknown } };
      data.scope = "notes";
      if (data.grant) data.grant.scope = "notes";
      row.value = JSON.stringify(data);
    }
    await unauthorized(await routeRequest(mcp(malformedToken, rpc("tools/call", {
      name: "cancel_item", arguments: CLOSED_CALL,
    })), malformedTokenEnv.env));
    assert.equal(malformedTokenEnv.d1.sessions.length, sessionsBefore);

    const revoked = fresh();
    const revokedToken = await issue(revoked.env);
    const revokedGrant = grantRecord(revoked.kv);
    revoked.kv.records.delete(revokedGrant.key);
    const revokedWrites = revoked.d1.writeBatches;
    await unauthorized(await routeRequest(mcp(revokedToken, rpc("tools/call", {
      name: "submit_result", arguments: CLOSED_CALL,
    })), revoked.env));
    assert.equal(revoked.d1.writeBatches, revokedWrites);

    const stale = fresh();
    const staleToken = await issue(stale.env);
    stale.d1.sqlite.prepare("UPDATE participant_credential SET owner_claimed_at = 'stale-lock' WHERE participant = 'dot'").run();
    const staleWrites = stale.d1.writeBatches;
    await unauthorized(await routeRequest(mcp(staleToken, rpc("tools/call", {
      name: "review_result", arguments: CLOSED_CALL,
    })), stale.env));
    assert.equal(stale.d1.writeBatches, staleWrites);

    const outage = fresh();
    const outageToken = await issue(outage.env);
    const sensitive = "synthetic-kv-timeout";
    const original = outage.kv.get.bind(outage.kv);
    outage.kv.get = async (key: string, options?: { type?: string }) => {
      if (key.startsWith("grant:")) throw new Error(sensitive);
      return original(key, options);
    };
    const outageWrites = outage.d1.writeBatches;
    const grantDown = await routeRequest(mcp(outageToken, rpc("tools/call", {
      name: "open_item", arguments: { ...CLOSED_CALL, idempotency_key: "req_kv_down_0001" },
    })), outage.env);
    assert.equal(grantDown.status, 503);
    const grantBody = await grantDown.text();
    assert.deepEqual(JSON.parse(grantBody), { error: "unavailable" });
    assert.equal(grantDown.headers.get("Cache-Control"), "no-store");
    assert.equal(grantBody.includes(sensitive), false);
    assert.equal(outage.d1.writeBatches, outageWrites);
    assert.match(logs.join("\n"), /"reason":"storage_unavailable"/);

    const tokenOutage = fresh();
    const tokenOutageToken = await issue(tokenOutage.env);
    const readsBefore = tokenOutage.d1.sessions.length;
    tokenOutage.kv.get = async () => { throw new Error(sensitive); };
    const tokenDown = await routeRequest(mcp(tokenOutageToken, rpc("tools/call", {
      name: "list_items", arguments: { box: "inbox" },
    })), tokenOutage.env);
    assert.equal(tokenDown.status, 503);
    assert.equal((await tokenDown.text()).includes(sensitive), false);
    assert.equal(tokenOutage.d1.sessions.length, readsBefore);
    clean(logs.join("\n"), [unknownToken, malformedGrantToken, malformedToken, revokedToken, staleToken, outageToken, tokenOutageToken, sensitive, GROK, GROK_HASH, EMAIL, CODE]);
  });

  it("refuses another origin, a missing origin, and a Dot token when OAuth storage is absent", async () => {
    captureLogs();
    const { d1, env } = fresh();
    const other = await routeRequest(new Request("https://evil.example/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${GROK}`, "Content-Type": "application/json" },
      body: JSON.stringify(rpc("ping")),
    }), env);
    assert.equal(other.status, 404);
    assert.equal(JSON.stringify(await other.json()).includes(GROK), false);
    const { OAUTH_KV: _kv, BRIDGE_ORIGIN: _origin, ...bare } = env;
    const sessionsBefore = d1.sessions.length;
    const unconfigured = await routeRequest(mcp("dot:synthetic:token", rpc("ping")), bare);
    assert.equal(unconfigured.status, 500);
    assert.deepEqual(await unconfigured.json(), { error: "internal_error" });
    assert.equal(d1.sessions.length, sessionsBefore);
    const grokStillWorks = await routeRequest(mcp(GROK, rpc("ping")), { ...bare, BRIDGE_ORIGIN: ORIGIN });
    assert.equal(grokStillWorks.status, 200);
    assert.equal(d1.sessions.length > 0, true);
    clean(logs.join("\n"), [GROK, EMAIL, CODE, "dot:synthetic:token"]);
  });
});
