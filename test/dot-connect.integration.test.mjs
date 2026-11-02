/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Integration tests using the verified official provider and ephemeral
 * workerd storage only. No remote bindings, client contacts or downloads.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare, NoOpLog, convertV4MiniflareOptions } from "miniflare";
import { Dispatcher, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { sqlStatements } from "./sql-statements.mjs";
import { readProviderArchive } from "../scripts/oauth-provider-artifact.mjs";

// Miniflare uses Undici's global dispatcher for host-side redirect targets.
// Deny them BEFORE DNS/connection establishment as well as using manual redirects.
// This guard is local to this test process; no machine settings change.
const originalDispatcher = getGlobalDispatcher();
let hostRefusals = 0;
setGlobalDispatcher(new class extends Dispatcher {
  dispatch(options, handler) {
    const hostname = new URL(options.origin).hostname;
    if (hostname !== "127.0.0.1" && hostname !== "[::1]") {
      hostRefusals++;
      handler.onError(new Error("test_nonlocal_host_request_refused"));
      return false;
    }
    return originalDispatcher.dispatch(options, handler);
  }
}());
after(() => { setGlobalDispatcher(originalDispatcher); });

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLIENT = "https://chatgpt.com/oauth/client.json";
const REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const ORIGIN = "https://bridge.invalid";
const RESOURCE = `${ORIGIN}/mcp`;
const sha = (value) => createHash("sha256").update(value).digest("hex");

async function bundle(contents) {
  const archive = await readProviderArchive();
  const provider = execFileSync("tar", ["-xzOf", "-", "package/dist/oauth-provider.js"], { input: archive, maxBuffer: 1024 * 1024 }).toString();
  const result = await build({
    stdin: { contents, resolveDir: ROOT, loader: "ts" }, bundle: true, write: false,
    format: "esm", platform: "neutral", target: "es2022", external: ["cloudflare:workers"], logLevel: "silent",
    plugins: [{ name: "cached-provider", setup(builder) {
      builder.onResolve({ filter: /^probe:provider$/ }, () => ({ path: "provider", namespace: "cached" }));
      // Neutral builds ignore package "main". Production imports the same pinned archive.
      builder.onResolve({ filter: /^@cloudflare\/workers-oauth-provider$/ }, () => ({ path: "provider", namespace: "cached" }));
      builder.onLoad({ filter: /.*/, namespace: "cached" }, () => ({ contents: provider, loader: "js" }));
    } }],
  });
  return result.outputFiles[0].text;
}

function localRuntime(script) {
  const calls = { metadata: 0, blocked: 0 };
  // This is a synthetic public-client document, not fetched ChatGPT metadata.
  // All worker fetches terminate here. There is deliberately no network fallback.
  const outboundService = (request) => {
    if (request.url !== CLIENT || request.method !== "GET") {
      calls.blocked++;
      return new Response(null, { status: 403 });
    }
    calls.metadata++;
    return Response.json({
      client_id: CLIENT, client_name: "Synthetic isolated client", redirect_uris: [REDIRECT],
      grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none",
    }, { headers: { "Cache-Control": "no-store" } });
  };
  const mf = new Miniflare(convertV4MiniflareOptions({
    host: "127.0.0.1", port: 0, inspectorPort: 0, inspectorHost: "127.0.0.1", cf: false,
    log: new NoOpLog(), kvPersist: false, d1Persist: false, cachePersist: false,
    workers: [{ name: "grant-provenance", modules: true, script, compatibilityDate: "2026-10-12",
      compatibilityFlags: ["global_fetch_strictly_public"], unsafeRegisterWorker: false,
      outboundService, kvNamespaces: ["OAUTH_KV"], d1Databases: ["DB"] }],
  }));
  const dispatch = (url, options = {}) => mf.dispatchFetch(url, { ...options, redirect: "manual" });
  return { mf, calls, dispatch };
}

test("local metadata interception gate with required runtime flag", { timeout: 60_000 }, async () => {
  const script = await bundle(`
    import { OAuthAuthorizationServer } from "probe:provider";
    const provider = new OAuthAuthorizationServer({ issuer: ${JSON.stringify(ORIGIN)}, resources: [${JSON.stringify(RESOURCE)}],
      tokenEndpoint: "/token", clientIdMetadataDocumentEnabled: true, onError: () => {} });
    export default { async fetch(request, env) {
      if (new URL(request.url).pathname === "/blocked") return fetch("https://blocked.invalid");
      const client = await provider.getOAuthApi(env).lookupClient(${JSON.stringify(CLIENT)});
      return Response.json({ enabled: Cloudflare.compatibilityFlags.global_fetch_strictly_public,
        client: client?.clientId, method: client?.tokenEndpointAuthMethod });
    } };
  `);
  const { mf, calls, dispatch } = localRuntime(script);
  try {
    const response = await dispatch(`${ORIGIN}/metadata-gate`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { enabled: true, client: CLIENT, method: "none" });
    assert.equal(calls.metadata, 1);
    assert.equal((await dispatch(`${ORIGIN}/blocked`)).status, 403);
    assert.equal(calls.blocked, 1, "unexpected destinations are intercepted and refused locally");
    const kv = await mf.getKVNamespace("OAUTH_KV");
    assert.equal((await kv.list()).keys.length, 0, "metadata lookup creates no grants or tokens");
    await assert.rejects(fetch("https://blocked.invalid"), (error) => error.cause?.message === "test_nonlocal_host_request_refused");
    assert.equal(hostRefusals, 1, "host networking is refused before any DNS or socket operation");
  } finally { await mf.dispose(); }
});

test("synthetic provider issuance through owner-bound connect completion and MCP", { timeout: 60_000 }, async (t) => {
  const { mf, calls, dispatch } = localRuntime(await bundle('export { default } from "./test/fixtures/dot-connect-worker.mjs";'));
  const now = Math.floor(Date.now() / 1000) * 1000;
  const owner = "2026-10-22T00:00:00.000Z", code = "s".repeat(43), verifier = "v".repeat(43);
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const expires = new Date(now + 600_000).toISOString();
  const sensitive = [code, verifier, "synthetic-owner@example.invalid"];
  let db, kv;
  const tables = ["item", "participant_credential", "connect_code", "bootstrap_secret_spend", "owner_lock"];
  async function config(mode = "", at = now) {
    const response = await dispatch(`${ORIGIN}/test/config`, { method: "POST", body: JSON.stringify({ mode, now: at }) });
    assert.equal(response.status, 204);
  }
  async function receipts() { return (await dispatch(`${ORIGIN}/test/receipts`)).json(); }
  async function snapshot() { return Promise.all(tables.map(async (table) => (await db.prepare(`SELECT * FROM ${table}`).all()).results)); }
  async function reset() {
    for (const trigger of ["fail_insert", "expire_after_revoke", "expire_after_insert"]) await db.prepare(`DROP TRIGGER IF EXISTS ${trigger}`).run();
    for (const table of tables) await db.prepare(`DELETE FROM ${table}`).run();
    await db.prepare("UPDATE participant SET enabled = 1").run();
    for (const { name } of (await kv.list()).keys) await kv.delete(name);
    await db.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").bind("synthetic-owner@example.invalid", owner).run();
    await db.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, ?, NULL)").bind(sha(code), owner, expires).run();
    await db.prepare(`INSERT INTO participant_credential
      (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at)
      VALUES ('old-dot', 'dot', 'oauth_grant', 'synthetic-old-hash', ?, ?)`).bind(owner, owner).run();
    await config();
  }
  async function authorize(overrides = {}, path = "/authorize") {
    const body = new URLSearchParams({ connect_code: code, client_id: CLIENT, redirect_uri: REDIRECT, resource: RESOURCE,
      response_type: "code", code_challenge_method: "S256", code_challenge: challenge, state: "synthetic-state", ...overrides });
    return dispatch(`${ORIGIN}${path}`, { method: "POST", body });
  }
  function authCode(redirect) {
    const url = new URL(redirect);
    assert.equal(`${url.origin}${url.pathname}`, REDIRECT);
    assert.equal(url.searchParams.get("iss"), ORIGIN);
    assert.equal(url.searchParams.get("state"), "synthetic-state");
    const value = url.searchParams.get("code"); assert.ok(value); sensitive.push(value); return value;
  }
  async function exchange(redirect, overrides = {}) {
    const body = new URLSearchParams({ grant_type: "authorization_code", client_id: CLIENT, redirect_uri: REDIRECT,
      resource: RESOURCE, code: authCode(redirect), code_verifier: verifier, ...overrides });
    const response = await dispatch(`${ORIGIN}/token`, { method: "POST", body });
    const result = await response.json();
    if (result.access_token) sensitive.push(result.access_token);
    if (result.refresh_token) sensitive.push(result.refresh_token);
    return { response, result };
  }
  async function mcp(token, write = false) {
    const body = write ? { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "open_item", arguments: {
      idempotency_key: "req_synthetic_provenance", kind: "task", title: "Synthetic provenance", body: "Untrusted test data only.",
      scope: { allowed_sources: [], allowed_resources: [] },
    } } } : { jsonrpc: "2.0", id: 1, method: "tools/list" };
    const response = await dispatch(RESOURCE, { method: "POST", headers: {
      "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
    const raw = await response.text();
    assert.ok(sensitive.every((value) => !raw.includes(value)), "MCP never echoes synthetic credential or owner data");
    return { response, result: JSON.parse(raw) };
  }
  async function rejected(response, status = 400) {
    assert.equal(response.status, status);
    assert.equal(response.headers.get("Location"), null);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.deepEqual(await response.json(), { error: status === 500 ? "internal_error" : "connection_failed" });
  }
  async function oldIntact(expiredClaim = false) {
    assert.equal((await db.prepare("SELECT revoked_at FROM participant_credential WHERE id = 'old-dot'").first())?.revoked_at, null);
    const used = (await db.prepare("SELECT used_at FROM connect_code").first())?.used_at;
    if (expiredClaim) {
      // Expired codes cannot release their pending claim. It must not become a spend.
      const { completions } = await receipts();
      assert.equal(completions.length, 1);
      assert.equal(used, JSON.stringify({ v: 1, kind: "pending", credential_id: completions[0].credential, until: now + 10_000 }));
    } else assert.equal(used, null);
    assert.equal((await db.prepare("SELECT count(*) AS n FROM participant_credential").first())?.n, 1);
  }
  async function orphanRejected() {
    const { completions } = await receipts(); assert.equal(completions.length, 1);
    const { response, result } = await exchange(completions[0].redirectTo);
    assert.equal(response.status, 200, "an orphan KV grant may still exchange locally");
    const before = await snapshot();
    const refused = await mcp(result.access_token, true);
    assert.equal(refused.response.status, 401); assert.deepEqual(refused.result, { error: "unauthorized" });
    assert.deepEqual(await snapshot(), before, "orphan token cannot mutate lifecycle storage");
  }
  try {
    // Hard gate before any issuance. A failure throws out of the enclosing test.
    const gate = await dispatch(`${ORIGIN}/test/metadata`);
    assert.equal(gate.status, 200);
    assert.deepEqual(await gate.json(), { enabled: true, client: CLIENT });
    assert.equal(calls.metadata, 1); assert.equal(calls.blocked, 0);
    db = await mf.getD1Database("DB"); kv = await mf.getKVNamespace("OAUTH_KV");
    assert.equal((await kv.list()).keys.length, 0);
    for (const file of (await readdir(resolve(ROOT, "migrations"))).sort()) {
      const sql = await readFile(resolve(ROOT, "migrations", file), "utf8");
      await db.batch(sqlStatements(sql).map((statement) => db.prepare(statement)));
    }
    await db.exec((await readFile(resolve(ROOT, "test/fixtures/connect-code.sql"), "utf8")).replace(/--[^\n]*/g, "").replace(/\n/g, " "));

    await t.test("provider-issued token proves S256 provenance, owner binding and a lifecycle write", async () => {
      await reset(); const response = await authorize(); assert.equal(response.status, 303);
      const redirect = response.headers.get("Location");
      const { calls: recorded, completions } = await receipts();
      assert.equal(recorded.completions, 1); assert.equal(recorded.writes, 2);
      assert.ok(recorded.sessions.every((value) => value === "first-primary"));
      assert.equal(completions[0].userId, "dot"); assert.deepEqual(completions[0].metadata, {});
      assert.deepEqual(completions[0].props, { credential_id: completions[0].credential });
      assert.equal(completions[0].revokeExistingGrants, false);
      assert.equal((await db.prepare("SELECT owner_claimed_at FROM participant_credential WHERE id = ?").bind(completions[0].credential).first())?.owner_claimed_at, owner);
      const issued = await exchange(redirect); assert.equal(issued.response.status, 200);
      assert.equal(issued.result.resource, RESOURCE); assert.equal(issued.result.expires_in, 3600);
      const opened = await mcp(issued.result.access_token, true);
      assert.equal(opened.response.status, 200); assert.equal(opened.result.result.isError, false);
      assert.equal(opened.result.result.structuredContent.item.sender, "dot");
      assert.equal(opened.result.result.structuredContent.item.recipient, "grok_bot");
      assert.equal(opened.result.result.structuredContent.item.untrusted, true);
      assert.equal(opened.result.result.structuredContent.item.owner_approval, "required");
      assert.equal((await db.prepare("SELECT count(*) AS n FROM item").first())?.n, 1);
      const replay = await exchange(redirect);
      assert.equal(replay.response.status, 400); assert.equal(replay.result.error, "invalid_grant");
    });
    await t.test("PKCE rejects missing and wrong verifiers; the correct verifier exchanges", async () => {
      await reset(); const response = await authorize(); assert.equal(response.status, 303);
      const redirect = response.headers.get("Location");
      for (const code_verifier of ["", "wrong-synthetic-verifier".repeat(2)]) {
        const refused = await exchange(redirect, { code_verifier });
        assert.equal(refused.response.status, 400); assert.ok(["invalid_request", "invalid_grant"].includes(refused.result.error));
      }
      assert.equal((await exchange(redirect)).response.status, 200);
    });
    await t.test("successful reconnection revokes the previous provider-issued token", async () => {
      await reset(); const first = await authorize(); const old = await exchange(first.headers.get("Location"));
      assert.equal((await mcp(old.result.access_token)).response.status, 200);
      const nextCode = "n".repeat(43); sensitive.push(nextCode);
      await db.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, ?, NULL)").bind(sha(nextCode), owner, expires).run();
      const second = await authorize({ connect_code: nextCode }); assert.equal(second.status, 303);
      const current = await exchange(second.headers.get("Location"));
      assert.equal((await mcp(old.result.access_token)).response.status, 401);
      assert.equal((await mcp(current.result.access_token)).response.status, 200);
      assert.equal((await db.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").first())?.n, 1);
    });
    await t.test("sequential double submit replays the cached redirect and does not issue again", async () => {
      await reset();
      const first = await authorize();
      assert.equal(first.status, 303);
      const location = first.headers.get("Location");
      const before = await snapshot(), count = (await kv.list()).keys.length;
      const second = await authorize();
      assert.equal(second.status, 303);
      assert.equal(second.headers.get("Location"), location);
      assert.deepEqual(await snapshot(), before);
      assert.equal((await receipts()).calls.completions, 1);
      assert.equal((await kv.list()).keys.length, count);
    });
    await t.test("concurrent double submit returns one redirect and one credential", async () => {
      await reset();
      const responses = await (await authorize({}, "/test/race")).json();
      assert.deepEqual(responses.map((response) => response.status), [303, 303]);
      assert.equal(responses[0].location, responses[1].location);
      const recorded = await receipts();
      assert.ok(recorded.calls.writes >= 2);
      assert.equal(recorded.completions.length, 1);
      const issued = await exchange(responses[0].location);
      assert.equal(issued.response.status, 200);
      assert.equal((await mcp(issued.result.access_token)).response.status, 200);
      assert.equal((await db.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").first())?.n, 1);
    });
    for (const [name, override] of [
      ["wrong client", { client_id: "https://other.invalid/client.json" }],
      ["wrong redirect", { redirect_uri: "https://other.invalid/callback" }],
      ["plain PKCE", { code_challenge_method: "plain" }],
      ["forged owner", { owner_claimed_at: owner }],
    ]) await t.test(`${name} rejects before provider calls or metadata lookup`, async () => {
      await reset(); const before = await snapshot(), metadata = calls.metadata;
      await rejected(await authorize(override));
      assert.equal((await receipts()).calls.parses, 0); assert.equal(calls.metadata, metadata);
      assert.deepEqual(await snapshot(), before); assert.equal((await kv.list()).keys.length, 0);
    });
    for (const [name, sql] of [
      ["unknown code", "DELETE FROM connect_code"],
      ["spent code", "UPDATE connect_code SET used_at = 'synthetic-spent'"],
      ["wrong owner", "UPDATE connect_code SET owner_claimed_at = 'synthetic-other-owner'"],
      ["missing owner", "DELETE FROM owner_lock"],
      ["expired code", `UPDATE connect_code SET expires_at = '${new Date(now - 1).toISOString()}'`],
      ["exact expiry", `UPDATE connect_code SET expires_at = '${new Date(now).toISOString()}'`],
    ]) await t.test(`${name} issues nothing and preserves storage`, async () => {
      await reset(); await db.prepare(sql).run(); const before = await snapshot(), metadata = calls.metadata;
      await rejected(await authorize()); assert.deepEqual(await snapshot(), before);
      assert.equal((await receipts()).calls.parses, 0); assert.equal(calls.metadata, metadata);
      assert.equal((await kv.list()).keys.length, 0);
    });
    await t.test("just-before-expiry succeeds at the completion boundary", async () => {
      await reset(); await config("", now + 599_999); assert.equal((await authorize()).status, 303);
    });
    for (const mode of ["during-expiry", "queued-expiry", "during-reset"]) await t.test(`${mode} preserves the previous credential and rejects its orphan`, async () => {
      await reset(); await config(mode); await rejected(await authorize()); await oldIntact(mode !== "during-reset");
      await orphanRejected();
      const before = await snapshot();
      await rejected(await authorize());
      assert.deepEqual(await snapshot(), before);
      assert.equal((await receipts()).calls.completions, 1, "a rejected repeat issues no additional grant");
    });
    for (const mode of ["kv-before", "kv-after", "provider-after", "d1-before"]) await t.test(`${mode} fails safely without consuming authorization`, async () => {
      await reset(); await config(mode); const before = await snapshot();
      await rejected(await authorize(), 500); assert.deepEqual(await snapshot(), before); await oldIntact();
      if (mode === "kv-before") assert.equal((await kv.list()).keys.length, 0);
      else if (mode === "d1-before") assert.equal((await kv.list()).keys.length, 1);
      else assert.equal((await kv.list()).keys.length, 1);
      if (mode === "provider-after" || mode === "d1-before") await orphanRejected();
    });
    for (const [name, trigger] of [
      ["insertion failure", "CREATE TRIGGER fail_insert BEFORE INSERT ON participant_credential BEGIN SELECT RAISE(ABORT, 'synthetic-private-error'); END"],
      ["expiry after revocation", "CREATE TRIGGER expire_after_revoke AFTER UPDATE OF revoked_at ON participant_credential BEGIN UPDATE connect_code SET expires_at = '2000-01-01T00:00:00.000Z'; END"],
      ["expiry after insertion", "CREATE TRIGGER expire_after_insert AFTER INSERT ON participant_credential BEGIN UPDATE connect_code SET expires_at = '2000-01-01T00:00:00.000Z'; END"],
    ]) await t.test(`native D1 rolls back ${name}, including previous revocation`, async () => {
      await reset(); await db.prepare(trigger).run(); const before = await snapshot();
      await rejected(await authorize(), 500); assert.deepEqual(await snapshot(), before); await oldIntact();
      await orphanRejected();
    });
    await t.test("ambiguous D1 commit response returns no redirect and the same submit replays it", async () => {
      await reset(); await config("d1-after");
      const lost = await authorize();
      await rejected(lost, 500);
      const recorded = await receipts();
      assert.equal(recorded.calls.writes, 2);
      assert.equal(recorded.completions.length, 1);
      assert.equal((await db.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").first())?.n, 1);
      assert.notEqual((await db.prepare("SELECT used_at FROM connect_code").first())?.used_at, null);
      const replay = await authorize();
      assert.equal(replay.status, 303);
      assert.equal(replay.headers.get("Location"), recorded.completions[0].redirectTo);
      assert.equal((await receipts()).calls.completions, 1);
      assert.equal((await receipts()).calls.writes, 2);
    });
    await t.test("production entrypoint fails closed without a configured origin", async () => {
      for (const path of ["/mcp", "/authorize", "/token"]) {
        const result = await dispatch(`${ORIGIN}/test/production?path=${encodeURIComponent(path)}`);
        assert.equal(result.status, 500);
        assert.deepEqual(await result.json(), { error: "internal_error" });
      }
    });
    await t.test("provider KV and tokens contain no owner-lock data; all fetches stayed local", async () => {
      for (const { name } of (await kv.list()).keys) {
        const value = await kv.get(name);
        for (const privateValue of [owner, "synthetic-owner@example.invalid", code]) {
          assert.ok(!name.includes(privateValue) && !value.includes(privateValue));
        }
      }
      assert.ok(calls.metadata > 0); assert.equal(calls.blocked, 0);
      assert.equal(hostRefusals, 1, "only the explicit host-denial gate exercised the guard");
    });
  } finally { await mf.dispose(); }

  await t.test("disposal leaves a fresh runtime with no previous local state", async () => {
    const fresh = localRuntime(await bundle('export default { fetch() { return new Response(null); } };'));
    try {
      assert.equal((await (await fresh.mf.getKVNamespace("OAUTH_KV")).list()).keys.length, 0);
      const freshDb = await fresh.mf.getD1Database("DB");
      assert.equal((await freshDb.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name = 'connect_code'").first())?.n, 0);
      assert.equal(fresh.calls.metadata, 0); assert.equal(fresh.calls.blocked, 0);
    } finally { await fresh.mf.dispose(); }
  });
});
