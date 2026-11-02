/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, it, mock } from "node:test";
import { URL as NodeURL } from "node:url";
import { DotAuthUnavailable, verifyDotOAuth, type DotOAuthDependencies } from "../src/dot-oauth.ts";
import { ParticipantDisabled } from "../src/participant-status.ts";
import { verifyGrokBearer } from "../src/grok-bearer.ts";
import { ItemLifecycle, ITEM_NOTICE } from "../src/item-lifecycle.ts";
import { handleMcpRequest, type McpAdapterDependencies } from "../src/mcp-adapter.ts";
import { SqliteD1 } from "./d1-sqlite.ts";

// Deterministic, synthetic credentials and provider results only. This fixture
// is NOT OAuth cryptographic validation, issuance, or a usable client grant.
const TOKEN = "dot:synthetic-grant:synthetic-access-token";
const OTHER_TOKEN = "dot:another-grant:another-synthetic-token";
const GROK_TOKEN = "admrn_gb_" + "g".repeat(43);
const RESOURCE = "https://bridge.invalid/mcp";
const CLIENT = "https://chatgpt.com/oauth/client.json";
const CLAIMED_AT = "2026-10-22T00:00:00.000Z";
const NOW = Date.parse("2026-10-22T12:00:00.000Z");
const EXPIRES_AT = NOW / 1000 + 3600;
const CREDENTIAL_ID = "synthetic-dot-credential";
const OPEN = {
  idempotency_key: "req_dot_oauth_1234", kind: "task", title: "Public research", body: "Return a short answer.",
  scope: { allowed_sources: [], allowed_resources: [] },
};
const ITEM_ID = "item_00000000-0000-4000-8000-000000000000";
const INIT = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "synthetic-client", version: "0" } };
const databases: SqliteD1[] = [];
const hash = (text: string) => createHash("sha256").update(text).digest("hex");
function context(id = CREDENTIAL_ID) {
  return { props: { credential_id: id }, audience: RESOURCE, expiresAt: EXPIRES_AT, scope: [], userId: "dot", clientId: CLIENT };
}
function rpc(method: string, params?: unknown) {
  return { jsonrpc: "2.0", id: 1, method, ...(params === undefined ? {} : { params }) };
}
function request(token: string | null = TOKEN, message: unknown = rpc("ping")) {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (token !== null) headers.set("Authorization", `Bearer ${token}`);
  return new Request(RESOURCE, { method: "POST", headers, body: JSON.stringify(message) });
}
function setup(seed = true) {
  const d1 = new SqliteD1(); databases.push(d1);
  let now = NOW;
  d1.sqlite.function("strftime", { varargs: true }, () => new Date(now).toISOString());
  const db = d1.binding(), lifecycle = new ItemLifecycle(db, () => now);
  const contexts = new Map<string, unknown>([[TOKEN, context()]]);
  const grantScopes = new Map<string, string[] | null>([["synthetic-grant", []], ["another-grant", []]]);
  const validateToken = mock.fn(async (resource: string, token: string) => resource === RESOURCE ? contexts.get(token) ?? null : null);
  const deps: DotOAuthDependencies = {
    db, resource: RESOURCE, validateToken, now: () => now,
    readGrantScope: async (userId, grantId) => userId === "dot" ? grantScopes.get(grantId) ?? null : null,
  };
  function owner(claimedAt = CLAIMED_AT) {
    d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run("synthetic-owner@example.invalid", claimedAt);
  }
  function credential(id = CREDENTIAL_ID, claimedAt = CLAIMED_AT) {
    d1.sqlite.prepare(`INSERT INTO participant_credential
      (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at)
      VALUES (?, 'dot', 'oauth_grant', ?, ?, ?)`).run(id, hash(`synthetic-code-${id}`), claimedAt, CLAIMED_AT);
  }
  if (seed) { owner(); credential(); }
  const verify = (req = request()) => verifyDotOAuth(req, deps);
  const send = (req: Request) => handleMcpRequest(req, {
    lifecycle,
    getPrincipal: async () => await verify(req) === "dot" ? "dot" : null,
  });
  return {
    d1, db, lifecycle, contexts, grantScopes, validateToken, deps, owner, credential, verify, send,
    setNow: (value: number) => { now = value; },
  };
}
function rows(d1: SqliteD1) {
  return ["owner_lock", "bootstrap_secret_spend", "participant", "participant_credential", "item"]
    .map((table) => d1.sqlite.prepare(`SELECT * FROM ${table}`).all());
}
async function unauthorized(response: Response) {
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "unauthorized" });
  // Absolute OAuth discovery remains the separately reviewed composition's job.
  assert.equal(response.headers.get("WWW-Authenticate"), "Bearer");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
}
const fixedError = (error: unknown) => error instanceof Error && error.message === "internal_error" && error.cause === undefined;
const unavailableError = (error: unknown) => error instanceof DotAuthUnavailable && error.message === "unavailable" && error.cause === undefined;
afterEach(() => { for (const db of databases.splice(0)) db.sqlite.close(); mock.restoreAll(); });

describe("unmounted Dot OAuth verifier boundary", () => {
  it("requires the provider result and one joined primary read, returns only dot and writes nothing", async () => {
    const f = setup(), before = rows(f.d1);
    assert.equal(await f.verify(), "dot");
    assert.deepEqual(f.validateToken.mock.calls[0].arguments, [RESOURCE, TOKEN]);
    assert.deepEqual(f.d1.sessions, ["first-primary"]);
    assert.equal(f.d1.prepared.length, 1);
    assert.match(f.d1.prepared[0], /^SELECT p\.id AS participant/);
    assert.match(f.d1.prepared[0], /JOIN owner_lock/);
    assert.match(f.d1.prepared[0], /c\.id = \?1/);
    assert.doesNotMatch(f.d1.prepared[0], /owner_email|synthetic|token_sha256|connect_code_sha256/);
    assert.deepEqual(rows(f.d1), before);
    assert.equal(f.d1.writeBatches, 0);
  });

  it("preserves opaque token bytes and the provider's case-insensitive Bearer parsing", async () => {
    const f = setup();
    for (const header of [`Bearer ${TOKEN}`, `bearer  ${TOKEN}`, `BEARER\t${TOKEN}`]) {
      const req = request(); req.headers.set("Authorization", header);
      assert.equal(await f.verify(req), "dot");
    }
    assert.equal(await f.verify(request(TOKEN.toUpperCase())), null);
    assert.equal(f.d1.sessions.length, 3);
    assert.equal(f.validateToken.mock.calls[3].arguments[1], TOKEN.toUpperCase());
  });

  it("rejects missing, malformed, repeated or Grok-prefixed headers before provider or D1 access", async () => {
    const f = setup();
    const headers = [null, "", "Bearer", "Bearer ", `Basic ${TOKEN}`, `Bearer ${TOKEN} extra`,
      `Bearer ${TOKEN}, Bearer ${TOKEN}`, `Bearer ${TOKEN},`, `Bearer ${GROK_TOKEN}`, "Bearer admrn_gb_invalid"];
    for (const header of headers) {
      const req = request(null);
      if (header !== null) req.headers.set("Authorization", header);
      assert.equal(await f.verify(req), null);
    }
    const repeated = request(); repeated.headers.append("Authorization", `Bearer ${TOKEN}`);
    assert.equal(await f.verify(repeated), null);
    assert.equal(f.validateToken.mock.callCount(), 0);
    assert.equal(f.d1.sessions.length, 0);
    assert.equal(f.d1.writeBatches, 0);
  });

  it("never obtains tokens, resource, credential ID or identity from URLs, bodies or participant headers", async () => {
    const f = setup();
    const req = new Request(`https://attacker.invalid/mcp/${TOKEN}?resource=${RESOURCE}&access_token=${TOKEN}`, {
      method: "POST", headers: { "X-Token": TOKEN, "X-Participant": "dot", "X-Resource": RESOURCE },
      body: JSON.stringify({ access_token: TOKEN, credential_id: CREDENTIAL_ID, principal: "dot", resource: RESOURCE }),
    });
    assert.equal(await f.verify(req), null);
    assert.equal(f.validateToken.mock.callCount(), 0);
    req.headers.set("Authorization", `Bearer ${TOKEN}`);
    Object.defineProperty(req, "url", { get() { throw new Error("must not inspect URL"); } });
    Object.defineProperty(req, "body", { get() { throw new Error("must not inspect body"); } });
    assert.equal(await f.verify(req), "dot");
    assert.deepEqual(f.validateToken.mock.calls[0].arguments, [RESOURCE, TOKEN]);
  });

  it("fails closed on non-canonical server resources before calling the provider or D1", async () => {
    const f = setup();
    for (const resource of ["", "/mcp", "http://bridge.invalid/mcp", "https://bridge.invalid/other", `${RESOURCE}/`,
      `${RESOURCE}?resource=x`, `${RESOURCE}#fragment`, "https://user:pass@bridge.invalid/mcp", "https://BRIDGE.invalid/mcp",
      "https://bridge.invalid:443/mcp", "https://bridge.invalid/a/../mcp"]) {
      f.deps.resource = resource;
      await assert.rejects(f.verify(), fixedError);
    }
    assert.equal(f.validateToken.mock.callCount(), 0);
    assert.equal(f.d1.sessions.length, 0);
  });

  it("requires verified Dot subject, exact ChatGPT client and audience, expiry, and closed credential props", async () => {
    const f = setup();
    const invalid = [null, undefined, false, [], {}, TOKEN,
      ...[null, 0, "", "grok_bot", "Dot"].map((userId) => ({ ...context(), userId })),
      ...[null, "", `${CLIENT}/`, "https://attacker.invalid/client.json"].map((clientId) => ({ ...context(), clientId })),
      ...[null, [], "", `${RESOURCE}/`, "https://another.invalid/mcp", "https://bridge.invalid/other"].map((audience) => ({ ...context(), audience })),
      ...[undefined, null, "future", NaN, Infinity, -Infinity].map((expiresAt) => ({ ...context(), expiresAt })),
      ...[undefined, null, [], {}, { credential_id: null }, { credential_id: 123 }, { credential_id: "" },
        { credential_id: CREDENTIAL_ID, principal: "dot" }, Object.create({ credential_id: CREDENTIAL_ID })].map((props) => ({ ...context(), props })),
      { ...context(), scope: "notes" }, { ...context(), scope: [1] }, { ...context(), scope: undefined }];
    for (const value of invalid) { f.contexts.set(TOKEN, value); assert.equal(await f.verify(), null); }
    assert.equal(f.d1.sessions.length, 0);
    assert.equal(f.d1.writeBatches, 0);
  });

  it("rejects unknown tokens and credentials, and binds credential IDs as data", async () => {
    const f = setup(), before = rows(f.d1);
    assert.equal(await f.verify(request(OTHER_TOKEN)), null);
    assert.equal(f.d1.sessions.length, 0);
    for (const id of ["missing-row", `${CREDENTIAL_ID}' OR 1=1 --`]) {
      f.contexts.set(TOKEN, context(id));
      assert.equal(await f.verify(), null);
    }
    assert.deepEqual(rows(f.d1), before);
    assert.ok(f.d1.prepared.every((sql) => !sql.includes(CREDENTIAL_ID)));
  });

  it("rejects at the exact access-token expiry and after it, including expiry during provider validation", async () => {
    const f = setup();
    f.setNow(EXPIRES_AT * 1000 - 1);
    assert.equal(await f.verify(), "dot");
    const reads = f.d1.sessions.length;
    for (const now of [EXPIRES_AT * 1000, EXPIRES_AT * 1000 + 1, EXPIRES_AT * 1000 + 60_000]) {
      f.setNow(now); assert.equal(await f.verify(), null);
    }
    f.setNow(NOW);
    f.deps.validateToken = async () => { f.setNow(EXPIRES_AT * 1000); return context(); };
    assert.equal(await f.verify(), null);
    assert.equal(f.d1.sessions.length, reads);
  });

  it("rechecks expiry after the grant-scope lookup", async () => {
    const f = setup();
    const readGrantScope = f.deps.readGrantScope;
    f.deps.readGrantScope = async (userId, grantId) => {
      const stored = await readGrantScope(userId, grantId);
      f.setNow(EXPIRES_AT * 1000 + 1);
      return stored;
    };
    assert.equal(await f.verify(), null);
    assert.equal(f.d1.writeBatches, 0);
  });

  it("rechecks expiry after D1 returns and fails closed on an invalid server clock", async () => {
    const f = setup(); let samples = 0;
    f.deps.now = () => ++samples === 1 ? NOW : EXPIRES_AT * 1000;
    assert.equal(await f.verify(), null);
    assert.equal(samples, 2);
    assert.equal(f.d1.sessions.length, 1);
    for (const value of [NaN, Infinity, -Infinity]) {
      f.deps.now = () => value;
      await assert.rejects(f.verify(), fixedError);
    }
    assert.equal(f.d1.sessions.length, 1);
  });

  it("rejects absent or reset owner locks, stale owner binding and revoked credentials", async () => {
    for (const mutation of [
      "DELETE FROM owner_lock",
      "UPDATE owner_lock SET claimed_at = '2026-10-23T00:00:00.000Z'",
      "UPDATE participant_credential SET owner_claimed_at = '2026-10-21T00:00:00.000Z'",
      "UPDATE participant_credential SET revoked_at = '2026-10-22T00:00:00.000Z'",
      "UPDATE participant_credential SET revoked_at = ''",
      "DELETE FROM participant_credential",
    ]) {
      const f = setup(); f.d1.sqlite.exec(mutation); const before = rows(f.d1);
      assert.equal(await f.verify(), null);
      assert.deepEqual(f.d1.sessions, ["first-primary"]);
      assert.deepEqual(rows(f.d1), before);
      assert.equal(f.d1.writeBatches, 0);
    }
  });

  it("temporarily pauses a disabled participant without writes and resumes the same token after enable", async () => {
    const f = setup();
    assert.equal(await f.verify(), "dot");
    f.d1.sqlite.exec("UPDATE participant SET enabled = 0 WHERE id = 'dot'");
    const before = rows(f.d1);
    await assert.rejects(f.verify(), ParticipantDisabled);
    const response = await f.send(request());
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("Retry-After"), "60");
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(response.headers.get("WWW-Authenticate"), null);
    assert.deepEqual(await response.json(), { error: "unavailable" });
    assert.deepEqual(rows(f.d1), before);
    assert.equal(f.d1.writeBatches, 0);
    f.d1.sqlite.exec("UPDATE participant SET enabled = 1 WHERE id = 'dot'");
    assert.equal(await f.verify(), "dot");
    assert.equal((await f.send(request())).status, 200);
  });

  it("refuses wrong participant or credential kinds even in constraint-bypassed corrupt test data", async () => {
    for (const mutation of ["UPDATE participant_credential SET participant = 'grok_bot'",
      "UPDATE participant_credential SET kind = 'bearer'", "UPDATE participant_credential SET participant = 'intruder'",
      "UPDATE participant SET enabled = 2 WHERE id = 'dot'", "DELETE FROM participant WHERE id = 'dot'"]) {
      const f = setup();
      f.d1.sqlite.exec("PRAGMA ignore_check_constraints = ON");
      f.d1.sqlite.exec("PRAGMA foreign_keys = OFF");
      f.d1.sqlite.exec(mutation);
      assert.equal(await f.verify(), null);
      assert.equal(f.d1.writeBatches, 0);
    }
  });

  it("rechecks current owner and revocation after asynchronous provider validation and between requests", async () => {
    for (const mutation of ["DELETE FROM owner_lock", "UPDATE participant_credential SET revoked_at = 'revoked'",
      "UPDATE participant SET enabled = 0 WHERE id = 'dot'"]) {
      const f = setup();
      assert.equal(await f.verify(), "dot");
      let release: (value: unknown) => void = () => {};
      const validation = new Promise<unknown>((resolve) => { release = resolve; });
      f.deps.validateToken = () => validation;
      const pending = f.verify();
      f.d1.sqlite.exec(mutation); release(context());
      if (mutation.includes("enabled = 0")) {
        await assert.rejects(pending, ParticipantDisabled);
        await assert.rejects(f.verify(), ParticipantDisabled);
      } else {
        assert.equal(await pending, null);
        assert.equal(await f.verify(), null);
      }
      assert.deepEqual(f.d1.sessions, ["first-primary", "first-primary", "first-primary"]);
    }
  });

  it("uses fixed errors for provider/storage failures without retaining causes, logging or fetching", async () => {
    const f = setup(), before = rows(f.d1), sensitive = "synthetic-private-error-detail";
    const logs = [mock.method(console, "log", () => {}), mock.method(console, "error", () => {}), mock.method(console, "warn", () => {})];
    const fetch = mock.method(globalThis, "fetch", () => { throw new Error("unexpected fetch"); });
    f.deps.validateToken = async () => { throw new Error(sensitive); };
    await assert.rejects(f.verify(), fixedError);
    assert.equal(f.d1.sessions.length, 0);
    f.deps.validateToken = f.validateToken;
    f.d1.failRead(new Error(sensitive));
    await assert.rejects(f.verify(), fixedError);
    f.d1.failRead(new Error(sensitive));
    const response = await f.send(request());
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: "internal_error" });
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(fetch.mock.callCount(), 0);
    assert.ok(logs.every((log) => log.mock.callCount() === 0));
    assert.deepEqual(rows(f.d1), before);
  });

  it("fails closed for missing auth tables and malformed D1 responses", async () => {
    const f = setup(); f.d1.sqlite.exec("DROP TABLE participant_credential");
    await assert.rejects(f.verify(), fixedError);
    const unavailable = new Proxy({} as D1Database, { get() { throw new Error("synthetic-storage-error"); } });
    f.deps.db = unavailable;
    await assert.rejects(f.verify(), fixedError);
    assert.equal(await f.verify(request(null)), null);
    for (const results of [[], [{ success: false, results: [] }], [{ success: true, results: null }]]) {
      const g = setup(), original = g.db.withSession.bind(g.db);
      mock.method(g.db, "withSession", (constraint?: Parameters<D1Database["withSession"]>[0]) => {
        const session = original(constraint);
        mock.method(session, "batch", async () => results);
        return session;
      });
      await assert.rejects(g.verify(), fixedError);
      assert.equal(g.d1.writeBatches, 0);
    }
  });

  it("gates every adapter method and tool before lifecycle access, including temporary participant pauses", async () => {
    const names = ["list_items", "get_item", "open_item", "claim_item", "submit_result", "review_result", "cancel_item"];
    const messages = [rpc("initialize", INIT), rpc("ping"), rpc("tools/list"), { jsonrpc: "2.0", method: "notifications/initialized" },
      ...names.map((name) => rpc("tools/call", { name, arguments: { ...OPEN, item_id: ITEM_ID, caller: "dot" } }))];
    for (const failure of ["missing", "unknown", "revoked", "disabled", "owner", "expired", "audience"]) {
      const f = setup(); let accesses = 0;
      if (failure === "revoked") f.d1.sqlite.exec("UPDATE participant_credential SET revoked_at = 'revoked'");
      if (failure === "disabled") f.d1.sqlite.exec("UPDATE participant SET enabled = 0 WHERE id = 'dot'");
      if (failure === "owner") f.d1.sqlite.exec("DELETE FROM owner_lock");
      if (failure === "expired") f.setNow(EXPIRES_AT * 1000);
      if (failure === "audience") f.contexts.set(TOKEN, { ...context(), audience: "https://another.invalid/mcp" });
      for (const message of messages) {
        const req = request(failure === "missing" ? null : failure === "unknown" ? OTHER_TOKEN : TOKEN, message);
        const deps: McpAdapterDependencies = {
          getPrincipal: async () => await f.verify(req) === "dot" ? "dot" : null,
          get lifecycle(): ItemLifecycle { accesses++; throw new Error("must not access lifecycle"); },
        };
        const response = await handleMcpRequest(req, deps);
        if (failure === "disabled") {
          assert.equal(response.status, 503);
          assert.equal(response.headers.get("Retry-After"), "60");
          assert.deepEqual(await response.json(), { error: "unavailable" });
        } else {
          await unauthorized(response);
        }
      }
      assert.equal(accesses, 0);
      assert.equal(f.d1.writeBatches, 0);
    }
  });

  it("preserves adapter transport prechecks before provider and storage access", async () => {
    const f = setup();
    const checks: Array<[Request, number]> = [
      [new Request(RESOURCE), 405], [new Request(RESOURCE, { method: "POST", body: "{}" }), 415],
      [new Request(RESOURCE, { method: "POST", headers: { "Content-Type": "application/json" }, body: "x".repeat(16 * 1024 + 1) }), 413],
    ];
    const version = request(); version.headers.set("MCP-Protocol-Version", "unsupported"); checks.push([version, 400]);
    for (const [req, status] of checks) assert.equal((await f.send(req)).status, status);
    assert.equal(f.validateToken.mock.callCount(), 0);
    assert.equal(f.d1.sessions.length, 0);
  });

  it("composes both verifier boundaries with the lifecycle in both directions, preserving replay and labels", async () => {
    for (const dotSends of [true, false]) {
      const f = setup();
      f.d1.sqlite.prepare(`INSERT INTO participant_credential
        (id, participant, kind, token_sha256, owner_claimed_at, created_at)
        VALUES ('synthetic-grok', 'grok_bot', 'bearer', ?, ?, ?)`).run(hash(GROK_TOKEN), CLAIMED_AT, CLAIMED_AT);
      const ownerBefore = f.d1.sqlite.prepare("SELECT * FROM owner_lock").all();
      async function call(dot: boolean, name: string, args: unknown) {
        const req = request(dot ? TOKEN : GROK_TOKEN, rpc("tools/call", { name, arguments: args }));
        const response = await handleMcpRequest(req, { lifecycle: f.lifecycle,
          getPrincipal: async () => dot ? await f.verify(req) === "dot" ? "dot" : null : verifyGrokBearer(req, f.db) });
        assert.equal(response.status, 200);
        const body = await response.json() as { result: { isError: boolean; structuredContent: Record<string, unknown>; content: unknown[] } };
        assert.deepEqual(body.result.content[0], { type: "text", text: ITEM_NOTICE });
        return body.result;
      }
      assert.equal((await f.send(request(TOKEN, rpc("initialize", INIT)))).status, 200);
      assert.equal((await f.send(request(TOKEN, { jsonrpc: "2.0", method: "notifications/initialized" }))).status, 202);
      const opened = await call(dotSends, "open_item", OPEN);
      const item = opened.structuredContent.item as { id: string; sender: string; recipient: string };
      assert.equal(item.sender, dotSends ? "dot" : "grok_bot");
      assert.equal(item.recipient, dotSends ? "grok_bot" : "dot");
      const args = { item_id: item.id };
      assert.deepEqual((await call(dotSends, "claim_item", args)).structuredContent, { error: "not_permitted" });
      assert.equal((await call(!dotSends, "claim_item", args)).structuredContent.execute, true);
      assert.equal((await call(!dotSends, "claim_item", args)).structuredContent.execute, false);
      const submission = { ...args, result: "Synthetic answer" };
      assert.equal((await call(!dotSends, "submit_result", submission)).isError, false);
      const review = { ...args, decision: "accept", checked: true, note: "Synthetic requester check." };
      assert.deepEqual((await call(!dotSends, "review_result", review)).structuredContent, { error: "not_permitted" });
      assert.equal((await call(dotSends, "review_result", review)).isError, false);
      assert.equal((await call(dotSends, "review_result", review)).structuredContent.replayed, true);
      assert.equal((await call(dotSends, "open_item", OPEN)).structuredContent.replayed, true);
      assert.equal((await call(!dotSends, "claim_item", args)).structuredContent.execute, false);
      const read = (await call(dotSends, "get_item", args)).structuredContent.item as Record<string, unknown>;
      assert.equal(read.state, "accepted");
      assert.equal(read.untrusted, true);
      assert.equal(read.owner_approval, "required");
      assert.equal(read.result_label, "checked_by_requester");
      const cancelled = (await call(dotSends, "open_item", { ...OPEN, idempotency_key: "req_dot_cancel_123" })).structuredContent.item as { id: string };
      assert.equal((await call(dotSends, "cancel_item", { item_id: cancelled.id })).isError, false);
      assert.equal((await call(!dotSends, "claim_item", { item_id: cancelled.id })).structuredContent.execute, false);
      assert.deepEqual(f.d1.sqlite.prepare("SELECT * FROM owner_lock").all(), ownerBefore);
    }
  });

  it("rejects forged participant names, credential IDs and resources without changing actor enforcement", async () => {
    const f = setup(), opened = await f.lifecycle.openItem("grok_bot", OPEN), args = { item_id: opened.item.id };
    const before = rows(f.d1);
    assert.equal((await f.send(request(TOKEN, rpc("initialize", { ...INIT, clientInfo: { name: "grok_bot", version: "forged" } })))).status, 200);
    const req = request(TOKEN, rpc("tools/call", { name: "cancel_item", arguments: args,
      _meta: { principal: "grok_bot", credential_id: "synthetic-grok", resource: "https://attacker.invalid/mcp" } }));
    req.headers.set("X-Participant", "grok_bot");
    const body = await (await f.send(req)).json() as { result: { structuredContent: unknown } };
    assert.deepEqual(body.result.structuredContent, { error: "not_permitted" });
    for (const extra of [{ caller: "grok_bot" }, { credential_id: "synthetic-grok" }, { resource: "https://attacker.invalid/mcp" }]) {
      const response = await f.send(request(TOKEN, rpc("tools/call", { name: "claim_item", arguments: { ...args, ...extra } })));
      const invalid = await response.json() as { result: { structuredContent: unknown } };
      assert.deepEqual(invalid.result.structuredContent, { error: "invalid_input" });
    }
    assert.deepEqual(rows(f.d1), before);
    assert.ok(f.validateToken.mock.calls.every((call) => call.arguments[0] === RESOURCE));
  });

  it("preserves items and spent claim admission across a synthetic Dot credential rotation", async () => {
    const f = setup(), opened = await f.lifecycle.openItem("grok_bot", OPEN), args = { item_id: opened.item.id };
    const claim = rpc("tools/call", { name: "claim_item", arguments: args });
    assert.equal((await f.send(request(TOKEN, claim))).status, 200);
    const before = f.d1.sqlite.prepare("SELECT * FROM item").all();
    f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ?").run(CLAIMED_AT);
    f.credential("synthetic-rotated-dot");
    f.contexts.set(OTHER_TOKEN, context("synthetic-rotated-dot"));
    await unauthorized(await f.send(request(TOKEN, claim)));
    const response = await f.send(request(OTHER_TOKEN, claim));
    const body = await response.json() as { result: { structuredContent: { execute: boolean } } };
    assert.equal(body.result.structuredContent.execute, false);
    assert.deepEqual(f.d1.sqlite.prepare("SELECT * FROM item").all(), before);
    f.d1.sqlite.exec("DELETE FROM owner_lock"); f.owner("2026-10-23T00:00:00.000Z");
    await unauthorized(await f.send(request(OTHER_TOKEN, claim)));
    assert.deepEqual(f.d1.sqlite.prepare("SELECT * FROM item").all(), before);
  });

  it("returns insufficient_scope only after an active grant would have succeeded", async () => {
    const f = setup();
    f.contexts.set(TOKEN, { ...context(), scope: ["notes"] });
    assert.deepEqual(await f.verify(), { decision: "insufficient_scope", scope: [] });
    assert.equal(f.d1.writeBatches, 0);
    f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ?").run(CLAIMED_AT);
    assert.equal(await f.verify(), null);
  });

  it("accepts the scope stored for the grant and rejects a mismatch, a missing grant, or a lookup error", async () => {
    const f = setup();
    f.contexts.set(TOKEN, { ...context(), scope: ["notes"] });
    f.grantScopes.set("synthetic-grant", ["notes"]);
    assert.equal(await f.verify(), "dot");
    f.grantScopes.set("synthetic-grant", ["notes", "extra"]);
    assert.deepEqual(await f.verify(), { decision: "insufficient_scope", scope: ["notes", "extra"] });
    f.grantScopes.set("synthetic-grant", null);
    assert.equal(await f.verify(), null);
    f.contexts.set(TOKEN, context());
    f.grantScopes.set("synthetic-grant", []);
    assert.equal(await f.verify(), "dot");
    assert.equal(await f.verify(request("dot:forged-grant:forged-secret")), null);
    f.deps.readGrantScope = () => Promise.reject(new Error("kv down"));
    await assert.rejects(f.verify(), unavailableError);
    assert.equal(f.d1.writeBatches, 0);
  });

  it("pins grant-id parsing to workers-oauth-provider 1.2.3", async () => {
    const root = JSON.parse(readFileSync(new NodeURL("../package.json", import.meta.url), "utf8")) as {
      dependencies: Record<string, string>;
    };
    const installed = JSON.parse(readFileSync(
      new NodeURL("../node_modules/@cloudflare/workers-oauth-provider/package.json", import.meta.url),
      "utf8",
    )) as { version: string };
    assert.equal(root.dependencies["@cloudflare/workers-oauth-provider"], "1.2.3");
    assert.equal(installed.version, "1.2.3");
    const f = setup();
    const looked: string[] = [];
    f.deps.readGrantScope = (userId, grantId) => {
      looked.push(`${userId}:${grantId}`);
      return Promise.resolve([]);
    };
    const rejected = [
      "dot:synthetic-grant:secret:extra",
      "dot::secret",
      "dot:grant.id:secret",
      `dot:${"g".repeat(129)}:secret`,
      "other:synthetic-grant:secret",
      "dot:synthetic-grant:",
    ];
    for (const token of rejected) {
      f.contexts.set(token, context());
      assert.equal(await f.verify(request(token)), null, token);
    }
    assert.deepEqual(looked, []);
    const grantId = "g".repeat(128);
    const accepted = `dot:${grantId}:secret`;
    f.contexts.set(accepted, context());
    assert.equal(await f.verify(request(accepted)), "dot");
    assert.deepEqual(looked, [`dot:${grantId}`]);
  });

  it("binds production /mcp to this verifier without embedding a fixture token", () => {
    const route = readFileSync(new NodeURL("../src/mcp-route.ts", import.meta.url), "utf8");
    const router = readFileSync(new NodeURL("../src/router.ts", import.meta.url), "utf8");
    assert.match(route, /verifyParticipantOAuth/);
    assert.match(router, /handleMcpRoute/);
    assert.doesNotMatch(route, /unwrapToken|synthetic-access-token/);
    assert.doesNotMatch(readFileSync(new NodeURL("../src/index.ts", import.meta.url), "utf8"), /dot-oauth|grok-bearer|mcp-adapter|item-lifecycle/);
  });
});
