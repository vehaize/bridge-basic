/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 * Synthetic test worker only. Test controls and grant receipts never exist in
 * the production entrypoint. No request is forwarded outside the harness.
 */
import { OAuthAuthorizationServer } from "probe:provider";
import { completeDotConnection } from "../../src/dot-connect.ts";
import { verifyDotOAuth } from "../../src/dot-oauth.ts";
import { handleMcpRequest } from "../../src/mcp-adapter.ts";
import { ItemLifecycle } from "../../src/item-lifecycle.ts";
import production from "../../src/index.ts";

const CLIENT = "https://chatgpt.com/oauth/client.json";
const REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const ORIGIN = "https://bridge.invalid";
const RESOURCE = `${ORIGIN}/mcp`;
const provider = new OAuthAuthorizationServer({ issuer: ORIGIN, resources: [RESOURCE], tokenEndpoint: "/token",
  clientIdMetadataDocumentEnabled: true, onError: () => {} });
let clock = Date.now(), mode = "", completions = [], calls = { parses: 0, completions: 0, writes: 0, sessions: [] };
let waiting = 0, release = () => {}, barrier = Promise.resolve();
Date.now = () => clock; // Test-only clock, unrelated to native SQLite's execution clock.

/** Same grant-record checks as production /mcp. A missing or malformed grant is not a scope. */
async function readGrantScope(kv, userId, grantId) {
  if (userId !== "dot" || !/^[A-Za-z0-9_-]{1,128}$/.test(grantId)) return null;
  const stored = await kv.get(`grant:${userId}:${grantId}`, { type: "json" });
  if (!stored || typeof stored !== "object" || Array.isArray(stored)) return null;
  if (stored.id !== grantId || stored.userId !== userId || stored.clientId !== CLIENT || !Array.isArray(stored.scope)
    || stored.scope.some((entry) => typeof entry !== "string")) return null;
  return stored.scope;
}

function binding(env) {
  return { withSession(constraint) {
    if (constraint !== "first-primary") throw new Error("test_non_primary");
    calls.sessions.push(constraint);
    const session = env.DB.withSession(constraint);
    return {
      prepare(sql) {
        const wrap = (native) => ({ sql, native, bind: (...values) => wrap(native.bind(...values)) });
        return wrap(session.prepare(sql));
      },
      async batch(statements) {
        const writing = statements.some(({ sql }) => !/^\s*SELECT\b/i.test(sql));
        const spends = statements.some(({ sql }) => sql.includes("SET used_at = ?3"));
        if (writing) {
          calls.writes++;
          if (mode === "d1-before" && spends) throw new Error("synthetic-private-d1-error");
          // Expire at the final spend, after issuance; the earlier claim is also a write.
          if (mode === "queued-expiry" && spends) await env.DB.prepare("UPDATE connect_code SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").run();
        }
        const result = await session.batch(statements.map(({ native }) => native));
        if (spends && mode === "d1-after") throw new Error("synthetic-lost-commit-response");
        return result;
      },
    };
  } };
}

const worker = { async fetch(request, env, ctx) {
  const path = new URL(request.url).pathname;
  if (path === "/test/config") {
    const config = await request.json(); clock = config.now; mode = config.mode ?? "";
    completions = []; calls = { parses: 0, completions: 0, writes: 0, sessions: [] }; waiting = 0;
    barrier = Promise.resolve();
    return new Response(null, { status: 204 });
  }
  if (path === "/test/receipts") return Response.json({ calls, completions });
  if (path === "/test/race") {
    // Two independently entered completion calls share one workerd request
    // context so a test barrier doesn't outlive its owning request context.
    const body = await request.text();
    const attempt = () => worker.fetch(new Request(`${ORIGIN}/authorize`, { method: "POST", body,
      headers: { "Content-Type": "application/x-www-form-urlencoded" } }), env, ctx);
    const responses = await Promise.all([attempt(), attempt()]);
    return Response.json(responses.map((response) => ({ status: response.status, location: response.headers.get("Location") })));
  }
  if (path === "/test/production") {
    const target = new URL(request.url).searchParams.get("path");
    return production.fetch(new Request(`${ORIGIN}${target}`, { method: "POST" }), {}, ctx);
  }
  if (path === "/test/metadata") {
    const client = await provider.getOAuthApi(env).lookupClient(CLIENT);
    return Response.json({ enabled: Cloudflare.compatibilityFlags.global_fetch_strictly_public, client: client?.clientId });
  }
  if (path === "/authorize") {
    const providerEnv = { OAUTH_KV: {
      get: (...args) => env.OAUTH_KV.get(...args), list: (...args) => env.OAUTH_KV.list(...args),
      delete: (...args) => env.OAUTH_KV.delete(...args),
      async put(...args) {
        if (mode === "kv-before") throw new Error("synthetic-private-kv-error");
        await env.OAUTH_KV.put(...args);
        if (mode === "kv-after") throw new Error("synthetic-lost-kv-response");
      },
    } };
    const api = provider.getOAuthApi(providerEnv);
    return completeDotConnection(request, { db: binding(env), resource: RESOURCE, now: () => clock, oauth: {
      async parseAuthRequest(req) { calls.parses++; return api.parseAuthRequest(req); },
      async completeAuthorization(options) {
        calls.completions++;
        const result = await api.completeAuthorization(options);
        completions.push({ ...result, credential: options.props.credential_id, userId: options.userId,
          metadata: options.metadata, props: options.props, revokeExistingGrants: options.revokeExistingGrants });
        if (mode === "provider-after") throw new Error("synthetic-provider-response-lost");
        if (mode === "during-expiry") clock += 600_000;
        if (mode === "during-reset") await env.DB.prepare("UPDATE owner_lock SET claimed_at = 'synthetic-new-lock'").run();
        if (mode === "concurrent") {
          // Create the promise in the still-active first authorization request,
          // never in the already-completed configuration request context.
          if (waiting === 0) barrier = new Promise((resolve) => { release = resolve; });
          if (++waiting === 2) release();
          await barrier;
        }
        return result;
      },
    } });
  }
  if (path === "/token") {
    // Test dispatch only; production token request filtering remains unmounted.
    const params = new URLSearchParams(await request.clone().text());
    if (params.getAll("client_id").length !== 1 || params.get("client_id") !== CLIENT
      || params.get("redirect_uri") !== REDIRECT || params.has("client_assertion") || params.has("client_secret")
      || params.get("grant_type") !== "authorization_code") return Response.json({ error: "invalid_request" }, { status: 400 });
    return provider.fetch(request, env, ctx);
  }
  if (path === "/mcp") return handleMcpRequest(request, { lifecycle: new ItemLifecycle(binding(env), () => clock),
    getPrincipal: () => verifyDotOAuth(request, { db: binding(env), resource: RESOURCE, now: () => clock,
      validateToken: (audience, token) => provider.validateToken(audience, token, env),
      readGrantScope: (userId, grantId) => readGrantScope(env.OAUTH_KV, userId, grantId) }) });
  return new Response(null, { status: 404 });
} };
export default worker;
