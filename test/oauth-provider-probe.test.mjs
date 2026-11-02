/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Local-only probe. npm run test:provider prepares the verified official package.
 * This test never downloads, installs, serves consent, or touches deployed
 * bindings. Its refresh contracts issue synthetic local grants only.
 * Do not mount these test workers.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, webcrypto } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare, NoOpLog, convertV4MiniflareOptions } from "miniflare";
import { sqlStatements } from "./sql-statements.mjs";
import { readProviderArchive } from "../scripts/oauth-provider-artifact.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RESOURCE = "https://bridge.invalid/mcp";
const CLIENT = "https://chatgpt.com/oauth/client.json";
const CREDENTIAL_ID = "synthetic-probe-dot";
const CLAIMED_AT = "2026-10-22T00:00:00.000Z";
const NOW = Math.floor(Date.now() / 1000) * 1000;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const text = (value) => new TextEncoder().encode(value);

// This reproduces undocumented 1.2.3 storage/crypto details for fixtures ONLY.
// A fixed public test key and synthetic token have no production authority.
// The real provider code is loaded unchanged and does the unwrap/decrypt work.
async function syntheticRecord(wrappingConstant, ordinal, overrides = {}) {
  const grantId = String(ordinal).padStart(16, "0");
  const token = `dot:${grantId}:${"test".repeat(8)}`;
  const id = sha(token);
  const encryptionKey = await webcrypto.subtle.importKey("raw", new Uint8Array(32).fill(0x42), "AES-GCM", true, ["encrypt", "decrypt"]);
  const encryptedProps = b64(await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12) },
    encryptionKey, text(JSON.stringify({ credential_id: CREDENTIAL_ID }))));
  const hmac = await webcrypto.subtle.importKey("raw", wrappingConstant, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const derived = await webcrypto.subtle.sign("HMAC", hmac, text(token));
  const wrappingKey = await webcrypto.subtle.importKey("raw", derived, "AES-KW", false, ["wrapKey"]);
  const wrappedEncryptionKey = b64(await webcrypto.subtle.wrapKey("raw", encryptionKey, wrappingKey, "AES-KW"));
  return {
    token, key: `token:dot:${grantId}:${id}`,
    value: { id, grantId, userId: "dot", createdAt: NOW / 1000 - 60, expiresAt: NOW / 1000 + 3600,
      audience: RESOURCE, scope: [], wrappedEncryptionKey,
      grant: { clientId: CLIENT, scope: [], encryptedProps }, ...overrides },
  };
}

async function bundle(contents, providerSource) {
  const result = await build({
    stdin: { contents, resolveDir: ROOT, sourcefile: "local-oauth-probe.ts", loader: "ts" },
    bundle: true, write: false, format: "esm", platform: "neutral", target: "es2022",
    external: ["cloudflare:workers"], logLevel: "silent",
    plugins: [{ name: "cached-pinned-provider", setup(builder) {
      builder.onResolve({ filter: /^probe:oauth-provider$/ }, () => ({ path: "provider", namespace: "cached-provider" }));
      // Neutral builds ignore package "main". Production imports the same pinned archive.
      builder.onResolve({ filter: /^@cloudflare\/workers-oauth-provider$/ }, () => ({ path: "provider", namespace: "cached-provider" }));
      builder.onLoad({ filter: /.*/, namespace: "cached-provider" }, () => ({ contents: providerSource, loader: "js" }));
    } }],
  });
  return result.outputFiles[0].text;
}

function rpc(method, params) {
  return { jsonrpc: "2.0", id: 1, method, ...(params === undefined ? {} : { params }) };
}

test("cached provider → owner-bound Dot verifier → MCP, isolated workerd probe", { timeout: 60_000 }, async (t) => {
  const archive = await readProviderArchive();
  const providerSource = execFileSync("tar", ["-xzOf", "-", "package/dist/oauth-provider.js"], { input: archive, maxBuffer: 1024 * 1024 }).toString("utf8");
  const metadata = JSON.parse(execFileSync("tar", ["-xzOf", "-", "package/package.json"], { input: archive }).toString("utf8"));
  assert.equal(metadata.name, "@cloudflare/workers-oauth-provider");
  assert.equal(metadata.version, "1.2.3");
  const constant = /const WRAPPING_KEY_HMAC_KEY = new Uint8Array\(\[([\d,\s]+)\]\);/.exec(providerSource);
  assert.ok(constant, "pinned provider fixture layout must match exactly");
  const wrappingConstant = new Uint8Array(constant[1].split(",").map((part) => Number(part.trim())));
  assert.equal(wrappingConstant.length, 32);

  const script = await bundle(`
    import { OAuthAuthorizationServer } from "probe:oauth-provider";
    import { verifyDotOAuth } from "./src/dot-oauth.ts";
    import { handleMcpRequest } from "./src/mcp-adapter.ts";
    import { ItemLifecycle } from "./src/item-lifecycle.ts";
    const resource = ${JSON.stringify(RESOURCE)};
    // Test-only frozen clock, never derived from an HTTP request.
    Date.now = () => ${NOW};
    const provider = new OAuthAuthorizationServer({ issuer: "https://bridge.invalid", resources: [resource], onError: () => {} });
    const clientId = ${JSON.stringify(CLIENT)};
    async function readGrantScope(kv, userId, grantId) {
      if (userId !== "dot" || !/^[A-Za-z0-9_-]{1,128}$/.test(grantId)) return null;
      const stored = await kv.get(\`grant:\${userId}:\${grantId}\`, { type: "json" });
      if (!stored || typeof stored !== "object" || Array.isArray(stored)) return null;
      if (stored.id !== grantId || stored.userId !== userId || stored.clientId !== clientId || !Array.isArray(stored.scope)
        || stored.scope.some((entry) => typeof entry !== "string")) return null;
      return stored.scope;
    }
    export default { async fetch(request, env) {
      if (new URL(request.url).pathname !== "/mcp") return new Response(null, { status: 404 });
      const stats = { provider: "not-called", reads: 0, writes: 0, sessions: 0 };
      const refuseWrite = () => { stats.writes++; throw new Error("probe_write_refused"); };
      const providerEnv = { OAUTH_KV: {
        get: (...args) => { stats.reads++; return env.OAUTH_KV.get(...args); },
        put: refuseWrite, delete: refuseWrite, list: refuseWrite,
      } };
      const db = { withSession(constraint) {
        if (constraint !== "first-primary") throw new Error("probe_non_primary_read");
        stats.sessions++;
        return env.DB.withSession(constraint);
      } };
      const response = await handleMcpRequest(request, {
        lifecycle: new ItemLifecycle(db),
        getPrincipal: () => verifyDotOAuth(request, { db, resource, validateToken: async (audience, token) => {
          try {
            const result = await provider.validateToken(audience, token, providerEnv);
            stats.provider = result === null ? "rejected" : "accepted";
            return result;
          } catch { stats.provider = "error"; throw new Error("probe_provider_error"); }
        }, readGrantScope: (userId, grantId) => readGrantScope(providerEnv.OAUTH_KV, userId, grantId) }),
      });
      const headers = new Headers(response.headers);
      headers.set("X-Probe-Provider", stats.provider);
      headers.set("X-Probe-Kv-Reads", String(stats.reads));
      headers.set("X-Probe-Kv-Writes", String(stats.writes));
      headers.set("X-Probe-D1-Sessions", String(stats.sessions));
      return new Response(response.body, { status: response.status, headers });
    } };
  `, providerSource);
  const production = await bundle('export { default } from "./src/index.ts";', providerSource);
  let outboundCalls = 0;
  const outboundService = () => { outboundCalls++; return new Response(null, { status: 503 }); };
  const mf = new Miniflare(convertV4MiniflareOptions({
    host: "127.0.0.1", port: 0, inspectorPort: 0, inspectorHost: "127.0.0.1",
    cf: false, log: new NoOpLog(), kvPersist: false, d1Persist: false, cachePersist: false,
    workers: [
      { name: "local-oauth-probe", modules: true, script, compatibilityDate: "2026-10-12",
        unsafeRegisterWorker: false, outboundService, kvNamespaces: ["OAUTH_KV"], d1Databases: ["DB"] },
      { name: "production-router-check", modules: true, script: production, compatibilityDate: "2026-10-12",
        unsafeRegisterWorker: false, outboundService },
    ],
  }));
  try {
    await mf.ready;
    const db = await mf.getD1Database("DB", "local-oauth-probe");
    const kv = await mf.getKVNamespace("OAUTH_KV", "local-oauth-probe");
    for (const file of (await readdir(resolve(ROOT, "migrations"))).sort()) {
      const sql = await readFile(resolve(ROOT, "migrations", file), "utf8");
      await db.batch(sqlStatements(sql).map((statement) => db.prepare(statement)));
    }
    await db.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").bind("synthetic-owner@example.invalid", CLAIMED_AT).run();
    await db.prepare(`INSERT INTO participant_credential
      (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at)
      VALUES (?, 'dot', 'oauth_grant', ?, ?, ?)`).bind(CREDENTIAL_ID, sha("synthetic-connect-code"), CLAIMED_AT, CLAIMED_AT).run();

    let ordinal = 0;
    const fixtures = [];
    async function seed(overrides = {}) {
      const fixture = await syntheticRecord(wrappingConstant, ++ordinal, overrides);
      await kv.put(fixture.key, JSON.stringify(fixture.value));
      fixtures.push(fixture);
      const grantScope = Array.isArray(fixture.value.scope) ? fixture.value.scope : [];
      const grant = {
        token: fixture.token,
        key: `grant:dot:${fixture.value.grantId}`,
        value: { id: fixture.value.grantId, userId: "dot", clientId: CLIENT, scope: grantScope },
      };
      await kv.put(grant.key, JSON.stringify(grant.value));
      fixtures.push(grant);
      return fixture.token;
    }
    const valid = await seed();
    async function call(token, message = rpc("tools/list")) {
      const headers = { "Content-Type": "application/json" };
      if (token !== null) headers.Authorization = `Bearer ${token}`;
      const response = await mf.dispatchFetch(RESOURCE, { method: "POST", headers, body: JSON.stringify(message) });
      assert.equal(response.headers.get("X-Probe-Kv-Writes"), "0", "validation must never write KV");
      const raw = await response.text();
      assert.ok(!raw.includes("synthetic-owner@example.invalid"), "response omits owner data");
      assert.ok(!raw.includes(CREDENTIAL_ID), "response omits credential ID");
      assert.ok(fixtures.every((fixture) => !raw.includes(fixture.token)), "response omits tokens");
      return { response, body: raw ? JSON.parse(raw) : null };
    }
    async function snapshot() {
      return Promise.all(["owner_lock", "bootstrap_secret_spend", "participant", "participant_credential", "item"]
        .map(async (table) => (await db.prepare(`SELECT * FROM ${table}`).all()).results));
    }
    async function refuses(token, provider, status = 401, sessions = "0") {
      const before = await snapshot();
      const { response, body } = await call(token, rpc("tools/call", { name: "open_item", arguments: {
        idempotency_key: "req_probe_refused", kind: "task", title: "Synthetic refusal", body: "Must not create an item.",
      } }));
      assert.equal(response.status, status);
      assert.deepEqual(body, { error: status === 401 ? "unauthorized" : status === 503 ? "unavailable" : "internal_error" });
      if (status === 503) assert.equal(response.headers.get("Retry-After"), "60");
      assert.equal(response.headers.get("X-Probe-Provider"), provider);
      assert.equal(response.headers.get("X-Probe-D1-Sessions"), sessions);
      assert.equal(response.headers.get("Cache-Control"), "no-store");
      assert.deepEqual(await snapshot(), before);
    }

    await t.test("real validation unwraps/decrypts the fixture and reaches MCP discovery and lifecycle", async () => {
      const discovery = await call(valid);
      assert.equal(discovery.response.status, 200);
      assert.equal(discovery.response.headers.get("X-Probe-Provider"), "accepted");
      assert.equal(discovery.response.headers.get("X-Probe-Kv-Reads"), "2");
      assert.equal(discovery.response.headers.get("X-Probe-D1-Sessions"), "1");
      assert.equal(discovery.body.result.tools.length, 7);
      const opened = await call(valid, rpc("tools/call", { name: "open_item", arguments: {
        idempotency_key: "req_synthetic_probe", kind: "task", title: "Synthetic probe", body: "Test data grants no authority.",
        scope: { allowed_sources: [], allowed_resources: [] },
      } }));
      assert.equal(opened.response.status, 200);
      assert.equal(opened.body.result.isError, false);
      assert.equal(opened.body.result.structuredContent.item.sender, "dot");
      assert.equal(opened.body.result.structuredContent.item.recipient, "grok_bot");
      assert.equal(opened.body.result.structuredContent.item.untrusted, true);
      assert.equal(opened.body.result.structuredContent.item.owner_approval, "required");
    });
    await t.test("missing and malformed tokens are rejected without lifecycle access", async () => {
      await refuses(null, "not-called");
      await refuses("synthetic-malformed", "rejected");
    });
    await t.test("unknown or altered token material cannot authenticate", async () => {
      await refuses(`${valid}changed`, "rejected");
      await refuses("dot:0000000000000000:unknown-synthetic-material", "rejected");
    });
    await t.test("provider rejects a token bound to another resource", async () => {
      await refuses(await seed({ audience: "https://other.invalid/mcp" }), "rejected");
    });
    await t.test("provider rejects an expired token", async () => {
      await refuses(await seed({ expiresAt: NOW / 1000 - 1 }), "rejected");
    });
    await t.test("verifier rejects exact expiry even when the split provider returns a context", async () => {
      await refuses(await seed({ expiresAt: NOW / 1000 }), "accepted");
    });
    await t.test("verifier rejects a provider context with the wrong participant", async () => {
      await refuses(await seed({ userId: "grok_bot" }), "accepted");
    });
    await t.test("verifier rejects a provider context with the wrong client", async () => {
      const fixture = await syntheticRecord(wrappingConstant, ++ordinal);
      fixture.value.grant.clientId = "https://other.invalid/client.json";
      await kv.put(fixture.key, JSON.stringify(fixture.value)); fixtures.push(fixture);
      await refuses(fixture.token, "accepted");
    });
    await t.test("corrupt encrypted storage fails safely with a fixed internal error", async () => {
      await refuses(await seed({ wrappedEncryptionKey: "AAAA" }), "error", 500);
    });
    for (const [name, mutation, restore] of [
      ["revoked credential", "UPDATE participant_credential SET revoked_at = 'synthetic-revoked'", "UPDATE participant_credential SET revoked_at = NULL"],
      ["disabled participant", "UPDATE participant SET enabled = 0 WHERE id = 'dot'", "UPDATE participant SET enabled = 1 WHERE id = 'dot'"],
      ["stale credential owner", "UPDATE participant_credential SET owner_claimed_at = 'old-lock'", `UPDATE participant_credential SET owner_claimed_at = '${CLAIMED_AT}'`],
      ["reset owner lock", "UPDATE owner_lock SET claimed_at = 'new-lock'", `UPDATE owner_lock SET claimed_at = '${CLAIMED_AT}'`],
    ]) {
      await t.test(name + " rejects a cryptographically valid token", async () => {
        await db.prepare(mutation).run();
        try { await refuses(valid, "accepted", name === "disabled participant" ? 503 : 401, "1"); }
        finally { await db.prepare(restore).run(); }
      });
    }
    await t.test("missing owner lock rejects a cryptographically valid token", async () => {
      await db.prepare("DELETE FROM owner_lock").run();
      await refuses(valid, "accepted", 401, "1");
    });
    await t.test("production MCP and OAuth routes fail closed without a configured origin", async () => {
      const productionWorker = await mf.getWorker("production-router-check");
      for (const path of ["/mcp", "/authorize", "/token", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server"]) {
        const response = await productionWorker.fetch(`https://bridge.invalid${path}`, { method: "POST" });
        assert.equal(response.status, 500);
        assert.deepEqual(await response.json(), { error: "internal_error" });
      }
    });
    await t.test("validation leaves KV fixtures unchanged and makes no outbound requests", async () => {
      assert.equal(outboundCalls, 0);
      assert.equal((await kv.list()).keys.length, fixtures.length);
      for (const fixture of fixtures) assert.equal(await kv.get(fixture.key), JSON.stringify(fixture.value));
    });
  } finally {
    await mf.dispose();
  }
});

test("installed provider 1.2.3 refresh recovery policy, controlled clock and KV", { timeout: 60_000 }, async (t) => {
  const archive = await readProviderArchive();
  const providerSource = execFileSync("tar", ["-xzOf", "-", "package/dist/oauth-provider.js"],
    { input: archive, maxBuffer: 1024 * 1024 }).toString("utf8");
  const installed = await readFile(resolve(ROOT, "node_modules/@cloudflare/workers-oauth-provider/dist/oauth-provider.js"), "utf8");
  assert.equal(sha(installed), sha(providerSource), "installed provider must match the verified 1.2.3 artifact");
  const start = Date.parse("2026-10-28T00:00:00.000Z");
  const script = await bundle(`
    import { OAuthAuthorizationServer } from "probe:oauth-provider";
    let now = ${start}, mutations = 0, callbackMode = "", parallel = null;
    Date.now = () => now;
    const values = new Map();
    const kv = {
      async get(key, options) {
        const entry = values.get(key);
        const value = !entry || (entry.expiration !== undefined && entry.expiration <= now / 1000) ? null : entry.value;
        // Both parallel refreshes read the same pre-rotation grant, deterministically.
        if (parallel && key.startsWith("grant:")) {
          const barrier = parallel;
          barrier.reads++;
          if (barrier.reads === 2) { parallel = null; barrier.release(); }
          await barrier.wait;
        }
        return value === null ? null : options?.type === "json" ? JSON.parse(value) : value;
      },
      async put(key, value, options) {
        mutations++;
        values.set(key, { value, expiration: options?.expirationTtl === undefined ? undefined : now / 1000 + options.expirationTtl });
      },
      async delete(key) { mutations++; values.delete(key); },
      async list({ prefix = "" } = {}) {
        return { keys: [...values.keys()].filter(key => key.startsWith(prefix)).map(name => ({ name })), list_complete: true };
      },
    };
    const env = { OAUTH_KV: kv }, ctx = { waitUntil() {}, props: {} };
    const origin = "https://bridge.invalid", resource = ${JSON.stringify(RESOURCE)};
    const provider = new OAuthAuthorizationServer({ issuer: origin, resources: [resource],
      authorizeEndpoint: "/authorize", tokenEndpoint: "/token", accessTokenTTL: 3600, refreshTokenTTL: 2592000,
      tokenExchangeCallback(options) {
        if (options.grantType === "refresh_token" && callbackMode) throw new Error(callbackMode);
      }, onError() {} });
    const api = provider.getOAuthApi(env);
    async function requestToken(body) {
      return provider.fetch(new Request(origin + "/token", { method: "POST", body: new URLSearchParams(body) }), env, ctx);
    }
    export default { async fetch(request) {
      const path = new URL(request.url).pathname;
      if (path === "/test/reset") {
        values.clear(); now = ${start}; mutations = 0; callbackMode = ""; parallel = null;
        return new Response(null, { status: 204 });
      }
      if (path === "/test/config") {
        const config = await request.json();
        if (config.now !== undefined) now = config.now;
        if (config.callbackMode !== undefined) callbackMode = config.callbackMode;
        return new Response(null, { status: 204 });
      }
      if (path === "/test/parallel") {
        const { client, token } = await request.json();
        let release;
        const wait = new Promise(resolve => { release = resolve; });
        parallel = { reads: 0, wait, release };
        const responses = await Promise.all([0, 1].map(() => requestToken({
          grant_type: "refresh_token", client_id: client, refresh_token: token,
        })));
        return Response.json(await Promise.all(responses.map(async response => ({ status: response.status, body: await response.json() }))));
      }
      if (path === "/test/state") {
        return Response.json({ mutations, entries: [...values].map(([key, entry]) => [key, entry.value]) });
      }
      if (path === "/test/issue") {
        const client = await api.createClient({ redirectUris: ["https://client.invalid/callback"], tokenEndpointAuthMethod: "none" });
        const verifier = "v".repeat(43);
        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
        const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
        const params = new URLSearchParams({ client_id: client.clientId, redirect_uri: "https://client.invalid/callback",
          response_type: "code", resource, scope: "read write", code_challenge: challenge, code_challenge_method: "S256" });
        const authorization = await api.parseAuthRequest(new Request(origin + "/authorize?" + params));
        const completed = await api.completeAuthorization({ request: authorization, userId: "dot", scope: ["read", "write"],
          metadata: {}, props: { credential_id: "synthetic-refresh-contract" }, revokeExistingGrants: false });
        const response = await requestToken({ grant_type: "authorization_code", client_id: client.clientId,
          redirect_uri: "https://client.invalid/callback", resource, code_verifier: verifier,
          code: new URL(completed.redirectTo).searchParams.get("code") });
        return Response.json({ status: response.status, client: client.clientId, tokens: await response.json() });
      }
      if (path === "/test/validate") {
        const { token } = await request.json();
        return Response.json({ valid: await provider.validateToken(resource, token, env) !== null });
      }
      try { return await provider.fetch(request, env, ctx); }
      catch { return Response.json({ error: "test_callback_failed" }, { status: 500 }); }
    } };
  `, providerSource);
  let outboundCalls = 0;
  const mf = new Miniflare(convertV4MiniflareOptions({
    host: "127.0.0.1", port: 0, inspectorPort: 0, inspectorHost: "127.0.0.1", cf: false,
    log: new NoOpLog(), kvPersist: false, d1Persist: false, cachePersist: false,
    workers: [{ name: "refresh-contract", modules: true, script, compatibilityDate: "2026-10-12", unsafeRegisterWorker: false,
      outboundService: () => { outboundCalls++; return new Response(null, { status: 403 }); } }],
  }));
  const dispatch = (path, body) => mf.dispatchFetch(`https://bridge.invalid${path}`, {
    method: "POST", ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: "manual",
  });
  const config = async (body) => { assert.equal((await dispatch("/test/config", body)).status, 204); };
  const state = async () => (await dispatch("/test/state")).json();
  async function issue() {
    assert.equal((await dispatch("/test/reset")).status, 204);
    const result = await (await dispatch("/test/issue")).json();
    assert.equal(result.status, 200);
    assert.ok(typeof result.tokens.refresh_token === "string", "synthetic refresh issuance succeeded");
    return result;
  }
  async function refresh(client, token) {
    const response = await mf.dispatchFetch("https://bridge.invalid/token", { method: "POST", redirect: "manual",
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: client, refresh_token: token }) });
    const body = await response.json();
    return { status: response.status, body };
  }
  function accepted(result) {
    assert.equal(result.status, 200);
    assert.ok(typeof result.body.refresh_token === "string", "refresh issued a successor");
    return result.body.refresh_token;
  }
  async function refusedWithoutMutation(client, token) {
    const before = await state();
    const result = await refresh(client, token);
    assert.equal(result.status, 400); assert.equal(result.body.error, "invalid_grant");
    assert.ok(JSON.stringify(await state()) === JSON.stringify(before), "refused refresh preserves all KV entries and mutation count");
  }
  function grant(snapshot) {
    const entry = snapshot.entries.find(([key]) => key.startsWith("grant:"));
    assert.ok(entry, "synthetic grant remains present");
    return JSON.parse(entry[1]);
  }
  try {
    await t.test("immediate duplicate and repeated duplicate keep the same previous token and evict successors", async () => {
      const issued = await issue(), original = issued.tokens.refresh_token;
      const first = accepted(await refresh(issued.client, original));
      const firstState = await state();
      const second = accepted(await refresh(issued.client, original));
      assert.ok(second !== first, "duplicate creates another successor, not a replayed response");
      const secondState = await state();
      assert.equal(secondState.mutations - firstState.mutations, 2, "duplicate rewrites grant and creates access token");
      assert.equal(grant(secondState).previousRefreshTokenId, sha(original));
      assert.equal(grant(secondState).refreshTokenId, sha(second));
      await refusedWithoutMutation(issued.client, first);
      const third = accepted(await refresh(issued.client, original));
      assert.ok(third !== second, "repeated duplicate creates yet another successor");
      await refusedWithoutMutation(issued.client, second);
      assert.equal(grant(await state()).previousRefreshTokenId, sha(original));
    });
    await t.test("previous token has no timed grace and still rotates after seven days", async () => {
      const issued = await issue(), original = issued.tokens.refresh_token;
      accepted(await refresh(issued.client, original));
      const before = await state();
      await config({ now: start + 7 * 86400_000 });
      accepted(await refresh(issued.client, original));
      const after = await state();
      assert.equal(after.mutations - before.mutations, 2);
      assert.equal(grant(after).previousRefreshTokenId, sha(original));
      assert.equal(grant(after).expiresAt, grant(before).expiresAt, "refresh does not extend the original 30-day grant lifetime");
    });
    await t.test("grandparent reuse after a second generation is rejected without mutation", async () => {
      const issued = await issue(), original = issued.tokens.refresh_token;
      const first = accepted(await refresh(issued.client, original));
      const second = accepted(await refresh(issued.client, first));
      assert.equal(grant(await state()).previousRefreshTokenId, sha(first));
      assert.equal(grant(await state()).refreshTokenId, sha(second));
      await refusedWithoutMutation(issued.client, original);
    });
    await t.test("parallel refresh forks responses and one returned refresh successor is immediately invalid", async () => {
      const issued = await issue(), original = issued.tokens.refresh_token, before = await state();
      const results = await (await dispatch("/test/parallel", { client: issued.client, token: original })).json();
      const tokens = results.map(accepted);
      assert.ok(tokens[0] !== tokens[1], "parallel responses have distinct refresh tokens");
      const after = await state(), stored = grant(after);
      assert.equal(after.mutations - before.mutations, 4, "both refreshes write a grant and an access token");
      assert.equal(stored.previousRefreshTokenId, sha(original));
      const current = tokens.find(token => sha(token) === stored.refreshTokenId);
      const lost = tokens.find(token => sha(token) !== stored.refreshTokenId);
      assert.ok(current && lost, "only one returned successor survives as current");
      for (const result of results) {
        const validated = await (await dispatch("/test/validate", { token: result.body.access_token })).json();
        assert.equal(validated.valid, true, "both sibling access tokens remain valid");
      }
      await refusedWithoutMutation(issued.client, lost);
      accepted(await refresh(issued.client, current));
    });
    await t.test("reuse outside the grant lifetime is rejected without mutation", async () => {
      const issued = await issue(), original = issued.tokens.refresh_token;
      accepted(await refresh(issued.client, original));
      await config({ now: start + 30 * 86400_000 + 1000 });
      await refusedWithoutMutation(issued.client, original);
    });
    await t.test("neutral callback sentinel denies refresh without consuming or revoking the KV grant", async () => {
      const issued = await issue(), original = issued.tokens.refresh_token, before = await state();
      await config({ callbackMode: "bridge_refresh_paused" });
      const denied = await refresh(issued.client, original);
      assert.equal(denied.status, 500);
      assert.ok(JSON.stringify(await state()) === JSON.stringify(before), "neutral callback failure has no KV side effects");
      await config({ callbackMode: "" });
      accepted(await refresh(issued.client, original));
    });
    assert.equal(outboundCalls, 0, "all provider contracts stayed inside the local runtime");
  } finally { await mf.dispose(); }
});
