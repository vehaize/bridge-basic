/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, it, mock } from "node:test";
import { URL as NodeURL } from "node:url";
import { verifyGrokBearer } from "../src/grok-bearer.ts";
import { ParticipantDisabled } from "../src/participant-status.ts";
import { ItemLifecycle, ITEM_NOTICE } from "../src/item-lifecycle.ts";
import { handleMcpRequest, type McpAdapterDependencies } from "../src/mcp-adapter.ts";
import { SqliteD1 } from "./d1-sqlite.ts";

// Deterministic, synthetic test values only. No provisioning or real credentials.
const TOKEN = "admrn_gb_" + "a".repeat(43);
const OTHER_TOKEN = "admrn_gb_" + "b".repeat(43);
const CLAIMED_AT = "2026-10-22T00:00:00.000Z";
const NOW = Date.parse("2026-10-22T12:00:00.000Z");
const OPEN = {
  idempotency_key: "req_verifier_1234", kind: "task", title: "Public research", body: "Return a short answer.",
  scope: { allowed_sources: [], allowed_resources: [] },
};
const ITEM_ID = "item_00000000-0000-4000-8000-000000000000";
const INIT = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "synthetic-client", version: "0" } };
const databases: SqliteD1[] = [];
const hash = (token: string) => createHash("sha256").update(token).digest("hex");
function rpc(method: string, params?: unknown) {
  return { jsonrpc: "2.0", id: 1, method, ...(params === undefined ? {} : { params }) };
}
function request(token: string | null = TOKEN, message: unknown = rpc("ping")) {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (token !== null) headers.set("Authorization", `Bearer ${token}`);
  return new Request("https://bridge.invalid/mcp", { method: "POST", headers, body: JSON.stringify(message) });
}
function setup(seed = true) {
  const d1 = new SqliteD1(); databases.push(d1);
  d1.sqlite.function("strftime", { varargs: true }, () => new Date(NOW).toISOString());
  const db = d1.binding(), lifecycle = new ItemLifecycle(db, () => NOW);
  function owner(claimedAt = CLAIMED_AT) {
    d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run("synthetic-owner@example.invalid", claimedAt);
  }
  function credential(token = TOKEN, claimedAt = CLAIMED_AT, id = "synthetic-grok") {
    d1.sqlite.prepare(`INSERT INTO participant_credential
      (id, participant, kind, token_sha256, owner_claimed_at, created_at)
      VALUES (?, 'grok_bot', 'bearer', ?, ?, ?)`).run(id, hash(token), claimedAt, "2026-01-01T00:00:00.000Z");
  }
  if (seed) { owner(); credential(); }
  const verify = (req = request()) => verifyGrokBearer(req, db);
  const send = (req: Request) => handleMcpRequest(req, { lifecycle, getPrincipal: () => verify(req) });
  async function call(name: string, args: unknown) {
    const response = await send(request(TOKEN, rpc("tools/call", { name, arguments: args })));
    assert.equal(response.status, 200);
    return await response.json() as { result: { isError: boolean; structuredContent: Record<string, unknown>; content: Array<{ type: string; text: string }> } };
  }
  return { d1, db, lifecycle, owner, credential, verify, send, call };
}
function rows(d1: SqliteD1) {
  return ["owner_lock", "bootstrap_secret_spend", "participant", "participant_credential", "item"]
    .map((table) => d1.sqlite.prepare(`SELECT * FROM ${table}`).all());
}
async function unauthorized(response: Response) {
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "unauthorized" });
  assert.equal(response.headers.get("WWW-Authenticate"), "Bearer");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
}
afterEach(() => { for (const db of databases.splice(0)) db.sqlite.close(); mock.restoreAll(); });

describe("unmounted Grok bearer verifier", () => {
  it("creates only canonical participant/auth storage, with no owner, credentials, grants or item changes", () => {
    const f = setup(false);
    assert.deepEqual(f.d1.sqlite.prepare("SELECT id, enabled, wake_url FROM participant ORDER BY id").all().map((row) => ({ ...row })), [
      { id: "claude", enabled: 1, wake_url: null }, { id: "dot", enabled: 1, wake_url: null }, { id: "grok_bot", enabled: 1, wake_url: null },
    ]);
    for (const table of ["owner_lock", "bootstrap_secret_spend", "participant_credential", "item", "connect_code"]) {
      assert.equal(f.d1.sqlite.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get()?.count, 0);
    }
    f.owner(); f.credential();
    assert.throws(() => f.credential(OTHER_TOKEN, CLAIMED_AT, "second-active"), /UNIQUE constraint/);
    assert.throws(() => f.d1.sqlite.exec("UPDATE participant SET enabled = 2 WHERE id = 'grok_bot'"), /CHECK constraint/);
    assert.throws(() => f.d1.sqlite.exec("INSERT INTO participant (id) VALUES ('intruder')"), /CHECK constraint/);
    assert.throws(() => f.d1.sqlite.exec("UPDATE participant_credential SET participant = 'dot'"), /CHECK constraint/);
    assert.throws(() => f.d1.sqlite.exec("UPDATE participant_credential SET token_sha256 = NULL"), /CHECK constraint/);
    assert.throws(() => f.d1.sqlite.exec("UPDATE participant_credential SET kind = 'oauth_grant'"), /CHECK constraint/);
  });

  it("resolves only grok_bot using one joined primary read and no writes or sensitive result fields", async () => {
    const f = setup(), before = rows(f.d1);
    assert.equal(await f.verify(), "grok_bot");
    assert.deepEqual(f.d1.sessions, ["first-primary"]);
    assert.equal(f.d1.prepared.length, 1);
    assert.match(f.d1.prepared[0], /^SELECT p\.id AS participant/);
    assert.match(f.d1.prepared[0], /JOIN owner_lock/);
    assert.match(f.d1.prepared[0], /c\.token_sha256 = \?1/);
    assert.doesNotMatch(f.d1.prepared[0], /owner_email|synthetic-owner|admrn_gb_|[a-f0-9]{64}/);
    assert.equal(f.d1.writeBatches, 0);
    assert.deepEqual(rows(f.d1), before);
    const row = f.d1.sqlite.prepare("SELECT token_sha256 FROM participant_credential").get();
    assert.equal(row?.token_sha256, hash(TOKEN));
  });

  it("accepts case-insensitive Bearer schemes but preserves exact token prefix and bytes", async () => {
    const f = setup();
    for (const scheme of ["Bearer", "bearer", "BEARER", "bEaReR"]) {
      const req = request(); req.headers.set("Authorization", `${scheme}  ${TOKEN}`);
      assert.equal(await f.verify(req), "grok_bot");
    }
    const changedCase = request(TOKEN.replace("a".repeat(43), "A".repeat(43)));
    assert.equal(await f.verify(changedCase), null);
    assert.equal(await f.verify(request(TOKEN.replace("admrn_gb_", "ADMRN_GB_"))), null);
  });

  it("rejects missing, malformed, repeated and non-Bearer input before hashing or reading D1", async () => {
    const f = setup();
    const digest = mock.method(crypto.subtle, "digest", () => { throw new Error("unexpected hash"); });
    const malformed = [null, "", "Bearer", "Bearer ", `Basic ${TOKEN}`, `Bearer\t${TOKEN}`,
      `Bearer ${TOKEN.slice(0, -1)}`, `Bearer ${TOKEN}x`, `Bearer ${TOKEN}=`, `Bearer ${TOKEN.slice(0, -1)}+`,
      `Bearer ${TOKEN.slice(0, -1)}/`, `Bearer ${TOKEN}, Bearer ${TOKEN}`, `Bearer ${TOKEN} extra`,
      "Bearer admrn_gb_" + "a".repeat(10_000), "Bearer token-in-another-format", `Bearer ${TOKEN.replace("admrn_gb_", "ADMRN_GB_")}`];
    for (const header of malformed) {
      const req = request(null);
      if (header !== null) req.headers.set("Authorization", header);
      assert.equal(await f.verify(req), null);
    }
    const repeated = request(); repeated.headers.append("Authorization", `Bearer ${TOKEN}`);
    assert.equal(await f.verify(repeated), null);
    assert.equal(digest.mock.callCount(), 0);
    assert.equal(f.d1.sessions.length, 0);
    assert.equal(f.d1.prepared.length, 0);
  });

  it("ignores tokens in URLs, bodies and other headers and never chooses identity from them", async () => {
    const f = setup();
    const req = new Request(`https://bridge.invalid/mcp/${TOKEN}?access_token=${TOKEN}&principal=dot`, {
      method: "POST", headers: { "X-Token": TOKEN, "X-Participant": "dot" }, body: JSON.stringify({ token: TOKEN, principal: "dot" }),
    });
    assert.equal(await f.verify(req), null);
    assert.equal(f.d1.sessions.length, 0);
    req.headers.set("Authorization", `Bearer ${TOKEN}`);
    Object.defineProperty(req, "url", { get() { throw new Error("must not inspect URL"); } });
    Object.defineProperty(req, "body", { get() { throw new Error("must not inspect body"); } });
    assert.equal(await f.verify(req), "grok_bot");
  });

  it("rejects unknown tokens, missing or stale owner locks and revoked credentials", async () => {
    for (const change of [
      (f: ReturnType<typeof setup>) => f.d1.sqlite.exec("DELETE FROM owner_lock"),
      (f: ReturnType<typeof setup>) => f.d1.sqlite.prepare("UPDATE owner_lock SET claimed_at = ?").run("2026-10-23T00:00:00.000Z"),
      (f: ReturnType<typeof setup>) => f.d1.sqlite.prepare("UPDATE participant_credential SET owner_claimed_at = ?").run("2026-10-21T00:00:00.000Z"),
      (f: ReturnType<typeof setup>) => f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ?").run(CLAIMED_AT),
      (f: ReturnType<typeof setup>) => f.d1.sqlite.exec("UPDATE participant_credential SET revoked_at = ''"),
      (f: ReturnType<typeof setup>) => f.d1.sqlite.exec("DELETE FROM participant_credential"),
    ]) {
      const f = setup(); change(f); const before = rows(f.d1);
      assert.equal(await f.verify(), null);
      assert.deepEqual(f.d1.sessions, ["first-primary"]);
      assert.deepEqual(rows(f.d1), before);
      assert.equal(f.d1.writeBatches, 0);
    }
    const f = setup(), before = rows(f.d1);
    assert.equal(await f.verify(request(OTHER_TOKEN)), null);
    assert.deepEqual(rows(f.d1), before);
  });

  it("temporarily pauses a disabled participant without writes and resumes the same bearer after enable", async () => {
    const f = setup();
    f.d1.sqlite.exec("UPDATE participant SET enabled = 0 WHERE id = 'grok_bot'");
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
    f.d1.sqlite.exec("UPDATE participant SET enabled = 1 WHERE id = 'grok_bot'");
    assert.equal(await f.verify(), "grok_bot");
    assert.equal((await f.send(request())).status, 200);
  });

  it("refuses a wrong participant or credential kind even in constraint-bypassed synthetic corrupt rows", async () => {
    for (const mutation of [
      "UPDATE participant_credential SET participant = 'dot'",
      "UPDATE participant_credential SET kind = 'oauth_grant'",
      "UPDATE participant_credential SET participant = 'intruder'",
      "UPDATE participant SET enabled = 2 WHERE id = 'grok_bot'",
      "DELETE FROM participant WHERE id = 'grok_bot'",
    ]) {
      const f = setup();
      // Isolated negative fixtures only: never change production constraints.
      f.d1.sqlite.exec("PRAGMA ignore_check_constraints = ON");
      f.d1.sqlite.exec("PRAGMA foreign_keys = OFF");
      f.d1.sqlite.exec(mutation);
      assert.equal(await f.verify(), null);
      assert.equal(f.d1.writeBatches, 0);
    }
  });

  it("never authenticates Dot/OAuth or connect-code-shaped credentials, including expired ones", async () => {
    const f = setup();
    f.d1.sqlite.prepare(`INSERT INTO participant_credential
      (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at)
      VALUES ('synthetic-dot', 'dot', 'oauth_grant', ?, ?, ?)`).run(hash("synthetic-code"), CLAIMED_AT, CLAIMED_AT);
    // Fake OAuth-shaped strings with past and future expiries. This verifier
    // rejects both by format; it does not claim to validate OAuth expiry.
    for (const exp of [0, Math.floor(NOW / 1000) + 3600]) {
      const payload = Buffer.from(JSON.stringify({ sub: "dot", exp })).toString("base64url");
      assert.equal(await f.verify(request(`synthetic.${payload}.invalid-signature`)), null);
    }
    assert.equal(await f.verify(request("c".repeat(43))), null);
    assert.equal(f.d1.sessions.length, 0);
  });

  it("preserves static Grok token validity without inventing a time-based TTL", async () => {
    const f = setup();
    f.d1.sqlite.prepare("UPDATE participant_credential SET created_at = ?").run("2000-01-01T00:00:00.000Z");
    mock.method(Date, "now", () => Date.parse("2036-10-22T00:00:00.000Z"));
    assert.equal(await f.verify(), "grok_bot");
    f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ?").run(CLAIMED_AT);
    assert.equal(await f.verify(), null);
  });

  it("rechecks revocation, participant status and owner reset on every request without caching", async () => {
    const f = setup();
    assert.equal(await f.verify(), "grok_bot");
    f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ?").run(CLAIMED_AT);
    assert.equal(await f.verify(), null);
    f.credential(OTHER_TOKEN, CLAIMED_AT, "synthetic-rotated");
    assert.equal(await f.verify(request(OTHER_TOKEN)), "grok_bot");
    assert.equal(await f.verify(), null);
    f.d1.sqlite.exec("UPDATE participant SET enabled = 0 WHERE id = 'grok_bot'");
    await assert.rejects(f.verify(request(OTHER_TOKEN)), ParticipantDisabled);
    f.d1.sqlite.exec("UPDATE participant SET enabled = 1 WHERE id = 'grok_bot'");
    f.d1.sqlite.exec("DELETE FROM owner_lock");
    assert.equal(await f.verify(request(OTHER_TOKEN)), null);
    f.owner("2026-10-23T00:00:00.000Z");
    assert.equal(await f.verify(request(OTHER_TOKEN)), null);
    assert.equal(f.d1.sessions.length, 7);
    assert.ok(f.d1.sessions.every((value) => value === "first-primary"));
    assert.equal(f.d1.writeBatches, 0);
  });

  it("rejects unavailable storage with a fixed error, retaining no cause and producing no logs or fetches", async () => {
    const f = setup(), sensitive = "synthetic-private-database-detail";
    const logs = [mock.method(console, "log", () => {}), mock.method(console, "error", () => {})];
    const fetch = mock.method(globalThis, "fetch", () => { throw new Error("unexpected fetch"); });
    const fixed = (error: unknown) => error instanceof Error && error.message === "internal_error" && error.cause === undefined;
    f.d1.failRead(new Error(sensitive));
    await assert.rejects(f.verify(), fixed);
    const unavailable = new Proxy({} as D1Database, { get() { throw new Error(sensitive); } });
    await assert.rejects(verifyGrokBearer(request(), unavailable), fixed);
    // Missing header never reads even an unavailable database.
    assert.equal(await verifyGrokBearer(request(null), unavailable), null);
    f.d1.failRead(new Error(sensitive));
    const response = await f.send(request());
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: "internal_error" });
    assert.ok(logs.every((log) => log.mock.callCount() === 0));
    assert.equal(fetch.mock.callCount(), 0);
  });

  it("rejects missing auth tables safely rather than authenticating against only an owner lock", async () => {
    const f = setup();
    f.d1.sqlite.exec("DROP TABLE participant_credential");
    const response = await f.send(request());
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: "internal_error" });
    assert.equal(f.d1.writeBatches, 0);
  });

  it("gates every MCP method and tool before lifecycle access and keeps all authentication refusals identical", async () => {
    const names = ["list_items", "get_item", "open_item", "claim_item", "submit_result", "review_result", "cancel_item"];
    const messages = [rpc("initialize", INIT), rpc("ping"), rpc("tools/list"), { jsonrpc: "2.0", method: "notifications/initialized" },
      ...names.map((name) => rpc("tools/call", { name, arguments: { ...OPEN, item_id: ITEM_ID, caller: "dot" } }))];
    for (const token of [null, OTHER_TOKEN, "invalid-synthetic-credential"]) {
      const f = setup(); let accesses = 0;
      for (const message of messages) {
        const req = request(token, message);
        const deps: McpAdapterDependencies = {
          getPrincipal: () => f.verify(req),
          get lifecycle(): ItemLifecycle { accesses++; throw new Error("must not access lifecycle"); },
        };
        await unauthorized(await handleMcpRequest(req, deps));
      }
      assert.equal(accesses, 0);
      assert.equal(f.d1.writeBatches, 0);
    }
    const f = setup();
    for (const statement of [
      "UPDATE participant_credential SET revoked_at = '2026-10-22T00:00:00.000Z'",
      "UPDATE participant SET enabled = 0 WHERE id = 'grok_bot'",
      "DELETE FROM owner_lock",
    ]) {
      f.d1.sqlite.exec(statement);
      for (const message of messages) await unauthorized(await f.send(request(TOKEN, message)));
    }
  });

  it("preserves adapter transport prechecks before credential verification", async () => {
    const f = setup();
    for (const req of [
      new Request("https://bridge.invalid/mcp", { method: "GET" }),
      new Request("https://bridge.invalid/mcp", { method: "POST", body: "{}" }),
      new Request("https://bridge.invalid/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: "x".repeat(16 * 1024 + 1) }),
    ]) assert.ok([405, 415, 413].includes((await f.send(req)).status));
    const badVersion = request(); badVersion.headers.set("MCP-Protocol-Version", "unsupported");
    assert.equal((await f.send(badVersion)).status, 400);
    assert.equal(f.d1.sessions.length, 0);
  });

  it("composes the real verifier with the existing adapter for the Grok half of both lifecycle directions", async () => {
    for (const grokSends of [false, true]) {
      const f = setup();
      assert.equal((await f.send(request(TOKEN, rpc("initialize", INIT)))).status, 200);
      assert.equal((await f.send(request(TOKEN, { jsonrpc: "2.0", method: "notifications/initialized" }))).status, 202);
      // Dot is a service-only fixture here, not an authenticated Dot integration.
      const opened = grokSends ? (await f.call("open_item", OPEN)).result.structuredContent : await f.lifecycle.openItem("dot", OPEN);
      const item = opened.item as { id: string; sender: string; recipient: string };
      assert.equal(item.sender, grokSends ? "grok_bot" : "dot");
      assert.equal(item.recipient, grokSends ? "dot" : "grok_bot");
      const args = { item_id: item.id };
      const ownerBefore = f.d1.sqlite.prepare("SELECT * FROM owner_lock").all();
      if (grokSends) {
        await f.lifecycle.claimItem("dot", args);
        await f.lifecycle.submitResult("dot", { ...args, result: "Synthetic answer" });
        const reviewed = await f.call("review_result", { ...args, decision: "accept" });
        assert.equal(reviewed.result.isError, false);
      } else {
        assert.equal((await f.call("claim_item", args)).result.structuredContent.execute, true);
        assert.equal((await f.call("claim_item", args)).result.structuredContent.execute, false);
        assert.equal((await f.call("submit_result", { ...args, result: "Synthetic answer" })).result.isError, false);
        await f.lifecycle.reviewResult("dot", { ...args, decision: "accept" });
      }
      const read = (await f.call("get_item", args)).result;
      assert.equal(read.isError, false);
      assert.deepEqual(read.content[0], { type: "text", text: ITEM_NOTICE });
      const returned = read.structuredContent.item as Record<string, unknown>;
      assert.equal(returned.state, "accepted");
      assert.equal(returned.untrusted, true);
      assert.equal(returned.owner_approval, "required");
      assert.equal(returned.result_label, "unverified");
      assert.deepEqual(f.d1.sqlite.prepare("SELECT * FROM owner_lock").all(), ownerBefore);
    }
  });

  it("keeps actor enforcement under forged body, clientInfo, metadata and participant headers", async () => {
    const f = setup(), opened = await f.lifecycle.openItem("dot", OPEN), args = { item_id: opened.item.id };
    const before = rows(f.d1);
    assert.equal((await f.send(request(TOKEN, rpc("initialize", { ...INIT, clientInfo: { name: "dot", version: "forged" } })))).status, 200);
    const req = request(TOKEN, rpc("tools/call", { name: "cancel_item", arguments: args, _meta: { principal: "dot" } }));
    req.headers.set("X-Participant", "dot");
    const response = await f.send(req), body = await response.json() as { result: { isError: boolean; structuredContent: unknown } };
    assert.equal(body.result.isError, true);
    assert.deepEqual(body.result.structuredContent, { error: "not_permitted" });
    const forged = await f.call("cancel_item", { ...args, caller: "dot" });
    assert.deepEqual(forged.result.structuredContent, { error: "invalid_input" });
    assert.deepEqual(rows(f.d1), before);
  });

  it("preserves items and replay behavior across token rotation while revoking the old token", async () => {
    const f = setup(), opened = await f.lifecycle.openItem("dot", OPEN), args = { item_id: opened.item.id };
    assert.equal((await f.call("claim_item", args)).result.structuredContent.execute, true);
    const before = f.d1.sqlite.prepare("SELECT * FROM item").all();
    f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ?").run(CLAIMED_AT);
    f.credential(OTHER_TOKEN, CLAIMED_AT, "synthetic-rotated");
    await unauthorized(await f.send(request(TOKEN, rpc("tools/call", { name: "claim_item", arguments: args }))));
    const response = await f.send(request(OTHER_TOKEN, rpc("tools/call", { name: "claim_item", arguments: args })));
    const body = await response.json() as { result: { structuredContent: { execute: boolean } } };
    assert.equal(body.result.structuredContent.execute, false);
    assert.deepEqual(f.d1.sqlite.prepare("SELECT * FROM item").all(), before);
  });

  it("is wired from production /mcp without embedding a bearer", () => {
    const route = readFileSync(new NodeURL("../src/mcp-route.ts", import.meta.url), "utf8");
    assert.match(route, /verifyGrokBearer/);
    assert.doesNotMatch(route, new RegExp(TOKEN));
    assert.doesNotMatch(readFileSync(new NodeURL("../src/index.ts", import.meta.url), "utf8"), /grok-bearer|mcp-adapter|item-lifecycle/);
  });
});
