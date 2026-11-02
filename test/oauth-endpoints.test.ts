/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, it, mock } from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { OAuthAuthorizationServer, OAuthResourceServer } from "@cloudflare/workers-oauth-provider";
import { AUTHORIZE_CSP, consentPage } from "../src/consent-page.ts";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  CHATGPT_CLIENT_ID,
  CHATGPT_REDIRECT,
  CLAUDE_CLIENT_ID,
  CLAUDE_REDIRECT,
  REFRESH_TOKEN_TTL_SECONDS,
  authorizeSpendsAddressLimit,
  consentPostAllowed,
  handleOAuth,
  openAuthorizationServer,
  sameOriginPostAllowed,
  validateDotAccessToken,
  type BridgeEnv,
} from "../src/oauth-routes.ts";
import { routeRequest } from "../src/router.ts";
import { REFRESH_BUSY_RETRY_AFTER_SECONDS, REFRESH_PREVIOUS_GRACE_MS, RefreshFamilyBusy, RefreshFamilyExchange } from "../src/refresh-family.ts";
import * as familyPolicy from "../src/refresh-family.ts";
import { SqliteD1 } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";

const ORIGIN = "https://bridge.example";
const RESOURCE = `${ORIGIN}/mcp`;
const EMAIL = "synthetic-owner@example.invalid";
const OWNER = "2026-10-22T00:00:00.000Z";
const CODE = "c".repeat(43);
// Pinned refresh budget and the history bound derived from the fixed grant
// lifetime. Literals here keep the behavior tests meaningful without the fix.
const BUDGET_MS = 15 * 60_000;
const HISTORY_BOUND = 2 * (Math.floor(REFRESH_TOKEN_TTL_SECONDS * 1000 / BUDGET_MS) + 1) + 2;
const HASH = createHash("sha256").update(CODE).digest("hex");
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
  writes = 0;

  async get(key: string, options?: { type?: string }): Promise<unknown> {
    const row = this.records.get(key);
    if (!row || (row.expiresAt !== undefined && row.expiresAt <= Date.now() / 1000)) return null;
    return options?.type === "json" ? JSON.parse(row.value) as unknown : row.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number; expiration?: number; metadata?: unknown }): Promise<void> {
    this.writes += 1;
    const expiresAt = options?.expirationTtl !== undefined
      ? Math.floor(Date.now() / 1000) + options.expirationTtl
      : options?.expiration;
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
const fetches: string[] = [];
const logs: string[] = [];

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

function binding(d1: SqliteD1, kv: MemoryKv | undefined, origin: string | undefined = ORIGIN): BridgeEnv {
  return {
    DB: d1.binding(),
    ...(kv ? { OAUTH_KV: kv as unknown as KVNamespace } : {}),
    ...(origin === undefined ? {} : { BRIDGE_ORIGIN: origin }),
    OWNER_EMAIL: EMAIL,
    ...permissiveRateLimits(),
  };
}

function seed(d1: SqliteD1, hash = HASH): void {
  const expires = new Date(Date.now() + 600_000).toISOString();
  d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run(EMAIL, OWNER);
  d1.sqlite.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, ?, NULL)").run(hash, OWNER, expires);
  d1.sqlite.prepare(`INSERT INTO participant_credential
    (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at)
    VALUES ('old-dot', 'dot', 'oauth_grant', 'synthetic-old-hash', ?, ?)`).run(OWNER, OWNER);
}

function fresh(withOwner = true): { d1: SqliteD1; kv: MemoryKv; env: BridgeEnv } {
  const d1 = new SqliteD1();
  databases.push(d1);
  const kv = new MemoryKv();
  if (withOwner) seed(d1);
  return { d1, kv, env: binding(d1, kv) };
}

function authorizeQuery(challenge: string, extra: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    client_id: CHATGPT_CLIENT_ID,
    redirect_uri: CHATGPT_REDIRECT,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
    state: "synthetic-state",
    ...extra,
  });
  return `${ORIGIN}/authorize?${params}`;
}

function formBody(challenge: string, extra: Record<string, string> = {}): string {
  return new URLSearchParams({
    connect_code: CODE,
    client_id: CHATGPT_CLIENT_ID,
    redirect_uri: CHATGPT_REDIRECT,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
    state: "synthetic-state",
    ...extra,
  }).toString();
}

function postForm(url: string, body: string, headers: Record<string, string> = {}): Request {
  return new Request(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body,
  });
}

/** One extra field repeated twice, on top of an otherwise eligible token request. */
function withRepeatedField(fields: Record<string, string>, field: string): string {
  const params = new URLSearchParams(fields);
  params.append(field, "a");
  params.append(field, "b");
  return params.toString();
}

function assertClean(value: string, secrets: string[]): void {
  for (const secret of secrets) {
    assert.equal(value.includes(secret), false, "response or log contains a secret");
  }
}

function dumpedKv(kv: MemoryKv): string {
  return [...kv.records.entries()].map(([key, row]) => `${key}\n${row.value}`).join("\n");
}

async function issue(scope?: string): Promise<{
  d1: SqliteD1;
  kv: MemoryKv;
  env: BridgeEnv;
  access: string;
  refresh: string;
  verifier: string;
  code: string;
}> {
  const { verifier, challenge } = pkce();
  const { d1, kv, env } = fresh();
  const consented = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge, scope === undefined ? {} : { scope })), env);
  assert.equal(consented.status, 303);
  const location = consented.headers.get("Location");
  assert.ok(location);
  const code = new URL(location).searchParams.get("code");
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
  const body = await token.json() as { access_token?: string; refresh_token?: string; token_type?: string; expires_in?: number };
  assert.equal(body.token_type?.toLowerCase(), "bearer");
  assert.equal(typeof body.access_token, "string");
  assert.equal(typeof body.refresh_token, "string");
  assert.equal(body.expires_in, ACCESS_TOKEN_TTL_SECONDS);
  return { d1, kv, env, access: body.access_token ?? "", refresh: body.refresh_token ?? "", verifier, code };
}

function installFamilyMocks(): void {
  mock.method(globalThis, "fetch", async (input: unknown) => {
    const url = input instanceof Request ? input.url : String(input);
    assert.equal(url, CHATGPT_CLIENT_ID);
    return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
  });
  mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
  mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
}

function refreshGrant(env: BridgeEnv, token: string): Promise<Response> {
  return routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
    grant_type: "refresh_token", refresh_token: token, client_id: CHATGPT_CLIENT_ID,
  }).toString()), env);
}

function exchangeCode(env: BridgeEnv, code: string, verifier: string, clientId = CHATGPT_CLIENT_ID): Promise<Response> {
  return routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
    grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId,
    redirect_uri: clientId === CLAUDE_CLIENT_ID ? CLAUDE_REDIRECT : CHATGPT_REDIRECT, resource: RESOURCE,
  }).toString()), env);
}

function failTokenPutAfterGrant(kv: MemoryKv): { happened: () => boolean; restore: () => void } {
  const originalPut = kv.put.bind(kv);
  let savedGrant = false;
  let failedToken = false;
  kv.put = async (...args: Parameters<MemoryKv["put"]>) => {
    if (args[0].startsWith("token:")) {
      failedToken = true;
      throw new Error("KV PUT failed: 429 Too Many Requests");
    }
    await originalPut(...args);
    if (args[0].startsWith("grant:")) savedGrant = true;
  };
  return { happened: () => savedGrant && failedToken, restore: () => { kv.put = originalPut; } };
}

function revokeToken(env: BridgeEnv, token: string, hint?: "access_token" | "refresh_token", clientId = CHATGPT_CLIENT_ID): Promise<Response> {
  return routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
    token, ...(hint === undefined ? {} : { token_type_hint: hint }), client_id: clientId,
  }).toString()), env);
}

function ping(env: BridgeEnv, token: string): Promise<Response> {
  return routeRequest(new Request(RESOURCE, {
    method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
  }), env);
}

interface IssuedTokens {
  access_token: string;
  refresh_token: string;
  expires_in?: number;
}

async function rotated(env: BridgeEnv, token: string): Promise<IssuedTokens> {
  const response = await refreshGrant(env, token);
  assert.equal(response.status, 200);
  const body = await response.json() as IssuedTokens;
  assert.equal(typeof body.access_token, "string");
  assert.equal(typeof body.refresh_token, "string");
  return body;
}

/** One synthetic clock for the Bridge and the provider, advanced explicitly. */
function steppedClock(): (ms: number) => void {
  let now = Date.now();
  mock.method(Date, "now", () => now);
  return (ms) => { now += ms; };
}

function rowWrites(d1: SqliteD1): number {
  return Number(d1.sqlite.prepare("SELECT total_changes() AS n").get()?.n);
}

function family(d1: SqliteD1): {
  current_sha256: string; previous_sha256: string | null; previous_until_ms: number | null;
  previous_used: number; position: number; pending_id: string | null; revoked_at: string | null;
} {
  const rows = d1.sqlite.prepare("SELECT * FROM oauth_refresh_family").all();
  assert.equal(rows.length, 1);
  return rows[0] as unknown as ReturnType<typeof family>;
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function assertFamilyRevoked(d1: SqliteD1): void {
  assert.notEqual(family(d1).revoked_at, null);
  assert.equal(d1.sqlite.prepare(
    "SELECT count(*) AS n FROM participant_credential WHERE participant = 'dot' AND revoked_at IS NULL",
  ).get()?.n, 0);
}

async function assertRefused(env: BridgeEnv, token: string): Promise<void> {
  const response = await refreshGrant(env, token);
  assert.equal(response.status, 400);
  const body = await response.text();
  assert.deepEqual(JSON.parse(body), { error: "invalid_grant" });
  assertFamilyLogsClean([token], body);
}

function assertFamilyLogsClean(tokens: string[], errors = ""): void {
  const sensitive = tokens.flatMap((token) => [token, tokenHash(token), tokenHash(token).slice(0, 8)]);
  assertClean(`${logs.join("\n")}\n${errors}`, sensitive);
}

function assertUnavailableLog(event: string, reason: string): void {
  const entries = logs.filter((line) => line.startsWith("{")).map((line) => JSON.parse(line) as Record<string, unknown>);
  const matched = entries.filter((entry) => entry.event === event && entry.reason === reason);
  assert.ok(matched.length > 0, "temporary refusal must have a fixed diagnostic event");
  assert.ok(matched.every((entry) => isDeepStrictEqual(entry, { message: "bridge event", event, reason, status: 503 })),
    "temporary-refusal events must contain only fixed fields");
}

afterEach(() => {
  for (const db of databases.splice(0)) db.sqlite.close();
  fetches.length = 0;
  logs.length = 0;
  mock.restoreAll();
});

describe("Dot OAuth endpoints", () => {
  it("serves absolute metadata, enables CIMD, and leaves registration off", async () => {
    mock.method(globalThis, "fetch", () => { throw new Error("metadata must not fetch"); });
    mock.method(console, "log", () => {});
    const { env } = fresh(false);
    const protectedResource = await routeRequest(new Request(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`), env);
    assert.equal(protectedResource.status, 200);
    assert.equal(protectedResource.headers.get("Cache-Control"), "no-store");
    const resource = await protectedResource.json() as {
      resource: string;
      authorization_servers: string[];
      bearer_methods_supported: string[];
    };
    assert.deepEqual(resource, {
      resource: RESOURCE,
      authorization_servers: [ORIGIN],
      bearer_methods_supported: ["header"],
      resource_name: "ADMRN Bridge",
    });
    assert.equal(resource.authorization_servers[0]?.startsWith("https://"), true);

    const authorizationServer = await routeRequest(new Request(`${ORIGIN}/.well-known/oauth-authorization-server`), env);
    assert.equal(authorizationServer.status, 200);
    const metadata = await authorizationServer.json() as Record<string, unknown>;
    assert.equal(metadata.issuer, ORIGIN);
    assert.equal(metadata.authorization_endpoint, `${ORIGIN}/authorize`);
    assert.equal(metadata.token_endpoint, `${ORIGIN}/token`);
    assert.equal(metadata.revocation_endpoint, `${ORIGIN}/token`);
    assert.deepEqual(metadata.protected_resources, [RESOURCE]);
    assert.equal(metadata.authorization_response_iss_parameter_supported, true);
    assert.equal(metadata.client_id_metadata_document_supported, true);
    assert.deepEqual(metadata.grant_types_supported, ["authorization_code", "refresh_token"]);
    assert.deepEqual(metadata.response_types_supported, ["code"]);
    assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
    assert.equal("registration_endpoint" in metadata, false);
    assert.equal(JSON.stringify(metadata).includes(`"${ORIGIN}/`), true);
    assert.equal(JSON.stringify(metadata).includes("\"/authorize\""), false);

    const registered = await routeRequest(postForm(`${ORIGIN}/register`, "client_name=nope"), env);
    assert.equal(registered.status, 404);
    assert.deepEqual(await registered.json(), { ok: false, error: "not_found" });

    const otherHost = await routeRequest(new Request("https://evil.example/.well-known/oauth-authorization-server"), env);
    assert.equal(otherHost.status, 404);
    assert.equal(JSON.stringify(await otherHost.json()).includes("evil.example"), false);
    const { OAUTH_KV: _kv, ...noKv } = env;
    const publicMetadata = await routeRequest(new Request(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`), noKv);
    assert.equal(publicMetadata.status, 200);
  });

  it("renders an escaped consent page and writes nothing", async () => {
    mock.method(globalThis, "fetch", (input: unknown) => {
      fetches.push(input instanceof Request ? input.url : String(input));
      throw new Error("authorize GET must not fetch");
    });
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    const { verifier: _verifier, challenge } = pkce();
    const { d1, kv, env } = fresh();
    const state = `"><script>alert(1)</script><form action="https://evil.example">`;
    const scope = "<img src=x onerror=alert(1)>";
    const response = await routeRequest(new Request(authorizeQuery(challenge, { state, scope })), env);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(response.headers.get("X-Frame-Options"), "DENY");
    assert.equal(response.headers.get("Content-Security-Policy"), AUTHORIZE_CSP);
    assert.equal(response.headers.get("Referrer-Policy"), "same-origin");
    const html = await response.text();
    assert.match(html, /chatgpt\.com will connect as Dot/);
    assert.match(html, /Redirect URI: https:\/\/chatgpt.com\/connector_platform_oauth_redirect/);
    assert.match(html, /<p>Requested resource: https:\/\/bridge\.example\/mcp<\/p>/);
    assert.match(html, /<p>Requested scope: &lt;img src=x onerror=alert\(1\)&gt;<\/p>/);
    assert.match(html, /A requested scope does not limit which tools a token can use\./);
    assert.match(html, /<form method="post" action="\/authorize">/);
    assert.equal(html.split("<form").length, 2);
    assert.equal(html.includes("<script"), false);
    assert.equal(html.includes(EMAIL), false);
    assert.equal(html.includes(CODE), false);
    assert.match(html, /name="state" value="&quot;&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;&lt;form action=&quot;https:\/\/evil\.example&quot;&gt;"/);
    assert.match(html, /name="scope" value="&lt;img src=x onerror=alert\(1\)&gt;"/);
    assert.equal(d1.writeBatches, 0);
    assert.equal(kv.writes, 0);
    assert.deepEqual(fetches, []);
    assert.equal(d1.prepared.some((sql) => sql.includes(EMAIL) || sql.includes(CODE) || sql.includes(HASH)), false);
    assertClean(logs.join("\n"), [EMAIL, CODE, HASH, state]);
  });

  it("accepts bounded GET ui_locales for Dot and Claude without rendering, storing, or using the hint", async () => {
    mock.method(globalThis, "fetch", () => { throw new Error("authorize GET must not fetch"); });
    const { challenge } = pkce();
    const boundary = "en-" + Array(6).fill("abcdefgh").join("-") + "-abcdefg";
    assert.equal(boundary.length, 64);
    for (const [client_id, redirect_uri] of [
      [CHATGPT_CLIENT_ID, CHATGPT_REDIRECT], [CLAUDE_CLIENT_ID, CLAUDE_REDIRECT],
    ] as const) {
      const plain = fresh();
      const baseline = await routeRequest(new Request(authorizeQuery(challenge, { client_id, redirect_uri })), plain.env);
      assert.equal(baseline.status, 200);
      const expected = await baseline.text();
      for (const value of ["en-US", "vi en", "zh-Hant-TW", "aa bb cc dd ee ff gg hh", boundary]) {
        const { d1, kv, env } = fresh();
        let charged = 0;
        const guarded = { ...env, ...permissiveRateLimits(async () => { charged += 1; return { success: true }; }) };
        const response = await routeRequest(new Request(authorizeQuery(challenge, { client_id, redirect_uri, ui_locales: value })), guarded);
        assert.equal(response.status, 200, value);
        const html = await response.text();
        assert.equal(html, expected, value);
        assert.deepEqual([...response.headers], [...baseline.headers]);
        assert.equal(html.includes("ui_locales"), false);
        assert.equal(html.includes(value), false);
        assert.equal(charged, 0);
        assert.equal(d1.writeBatches, 0);
        assert.equal(kv.writes, 0);
        assert.equal(kv.records.size, 0);
      }
    }
  });

  it("rejects duplicate, unbounded, empty, malformed, or unsafe GET ui_locales as invalid_request", async () => {
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    mock.method(globalThis, "fetch", () => { throw new Error("invalid locales must not fetch"); });
    const { challenge } = pkce();
    const grok = `admrn_gb_${"a".repeat(43)}`;
    const oversized = "en-" + Array(6).fill("abcdefgh").join("-") + "-abcdefgh";
    assert.equal(oversized.length, 65);
    const values = ["", oversized, "aa bb cc dd ee ff gg hh ii", "<script>", "en_US", "en--US", "abcdefghi",
      "en-abcdefghi", "1n", " en", "en ", "vi  en", "vi\ten", "en\nUS", "en\u0000US", "en\u007fUS", grok];
    const requests = values.map((ui_locales) => new Request(authorizeQuery(challenge, { ui_locales })));
    const duplicate = new URL(authorizeQuery(challenge, { ui_locales: "en-US" }));
    duplicate.searchParams.append("ui_locales", "vi");
    requests.push(new Request(duplicate));
    for (const request of requests) {
      const { d1, kv, env } = fresh();
      const firstLog = logs.length;
      const response = await routeRequest(request, env);
      assert.equal(response.status, 400);
      const html = await response.text();
      assert.match(html, /Connection failed/);
      assert.ok(logs.slice(firstLog).some((line) => (JSON.parse(line) as { reason?: string }).reason === "invalid_request"));
      assertClean(html + logs.join("\n"), [grok]);
      assert.deepEqual(d1.sessions, []);
      assert.equal(d1.writeBatches, 0);
      assert.equal(kv.writes, 0);
    }
  });

  it("keeps unknown fields, connect_code, and unsafe state refused alongside GET ui_locales", async () => {
    const { challenge } = pkce();
    const extras: Record<string, string>[] = [{ foo: "bar" }, { prompt: "consent" }, { connect_code: CODE },
      { state: "unsafe\nstate" }, { state: `admrn_gb_${"a".repeat(43)}` }];
    for (const extra of extras) {
      const { d1, kv, env } = fresh();
      const response = await routeRequest(new Request(authorizeQuery(challenge, { ui_locales: "en-US", ...extra })), env);
      assert.equal(response.status, 400);
      assert.deepEqual(d1.sessions, []);
      assert.equal(d1.writeBatches, 0);
      assert.equal(kv.writes, 0);
    }
  });

  it("keeps owner-lock and reflected-connect-code gates for GET ui_locales", async () => {
    const { challenge } = pkce();
    const unlocked = fresh(false);
    assert.equal((await routeRequest(new Request(authorizeQuery(challenge, { ui_locales: "en-US" })), unlocked.env)).status, 400);
    const reflected = "en-" + ["aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"].join("-") + "-eeee";
    assert.equal(reflected.length, 43);
    const { d1, kv, env } = fresh(false);
    seed(d1, createHash("sha256").update(reflected).digest("hex"));
    const response = await routeRequest(new Request(authorizeQuery(challenge, { ui_locales: reflected })), env);
    assert.equal(response.status, 400);
    assert.equal((await response.text()).includes(reflected), false);
    assert.equal(d1.writeBatches, 0);
    assert.equal(kv.writes, 0);
  });

  it("keeps POST ui_locales refused before address quota, provider, or storage", async () => {
    mock.method(globalThis, "fetch", () => { throw new Error("POST locales must not fetch"); });
    const { challenge } = pkce();
    const { d1, kv, env } = fresh();
    let charged = 0;
    const guarded = { ...env, ...permissiveRateLimits(async () => { charged += 1; return { success: true }; }) };
    for (const ui_locales of ["en-US", "vi en"]) {
      const request = postForm(`${ORIGIN}/authorize`, formBody(challenge, { ui_locales }));
      assert.equal(await authorizeSpendsAddressLimit(request, guarded), false);
      const response = await routeRequest(request, guarded);
      assert.equal(response.status, 400);
      assert.match(await response.text(), /Connection failed/);
    }
    assert.equal(charged, 0);
    assert.deepEqual(d1.sessions, []);
    assert.equal(d1.writeBatches, 0);
    assert.equal(kv.writes, 0);
    assert.equal(d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, null);
  });

  it("warns Dot and Claude to use a self-started flow and that connecting revokes the current connection", async () => {
    const { challenge } = pkce();
    for (const [clientId, redirectUri, name] of [
      [CHATGPT_CLIENT_ID, CHATGPT_REDIRECT, "Dot"],
      [CLAUDE_CLIENT_ID, CLAUDE_REDIRECT, "Claude"],
    ] as const) {
      const { d1, kv, env } = fresh();
      const response = await routeRequest(new Request(authorizeQuery(challenge, { client_id: clientId, redirect_uri: redirectUri })), env);
      assert.equal(response.status, 200);
      const html = await response.text();
      assert.ok(html.includes("<p>Only enter a connect code or approve a connection you started yourself from your own ChatGPT or Claude settings.</p>"), name);
      assert.ok(html.includes(`<p>Completing this connection revokes and replaces the current ${name} connection.</p>`), name);
      assert.equal(d1.writeBatches, 0);
      assert.equal(kv.writes, 0);
    }
  });

  it("shows omitted and empty requested scopes explicitly on consent", async () => {
    const { challenge } = pkce();
    for (const [name, extra, expected] of [
      ["omitted", {}, "not supplied"],
      ["empty", { scope: "" }, "(empty)"],
    ] as const) {
      const { env } = fresh();
      const response = await routeRequest(new Request(authorizeQuery(challenge, extra)), env);
      assert.equal(response.status, 200, name);
      const html = await response.text();
      assert.ok(html.includes(`<p>Requested scope: ${expected}</p>`), name);
      assert.ok(html.includes(`<p>Requested resource: ${RESOURCE}</p>`), name);
    }
  });

  it("escapes resource and scope in the visible consent summary", () => {
    const resource = `${RESOURCE}?label=<script>"&'@`;
    const scope = `read<&"'@`;
    const html = consentPage({
      clientId: CHATGPT_CLIENT_ID,
      redirectUri: CHATGPT_REDIRECT,
      responseType: "code",
      codeChallenge: pkce().challenge,
      codeChallengeMethod: "S256",
      resource,
      scope,
      state: "synthetic-state",
    });
    assert.match(html, /<p>Requested resource: https:\/\/bridge\.example\/mcp\?label=&lt;script&gt;&quot;&amp;&#39;&#64;<\/p>/);
    assert.match(html, /<p>Requested scope: read&lt;&amp;&quot;&#39;&#64;<\/p>/);
    assert.equal(html.includes(resource), false);
    assert.equal(html.includes(scope), false);
    assert.equal(html.includes("<script>"), false);
  });

  it("sanitizes asynchronous failures from every OAuth response path", async () => {
    const raw = "synthetic-private-upstream-error";
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    const { env } = fresh();
    const malformedResponse = (): Response => {
      const response = new Response("synthetic response");
      Object.defineProperty(response, "headers", { get() { throw new Error(raw); } });
      return response;
    };
    const authorizationFetch = mock.method(OAuthAuthorizationServer.prototype, "fetch", async () => malformedResponse());
    mock.method(OAuthResourceServer.prototype, "fetch", async () => malformedResponse());
    const authorizeRequest = new Request(authorizeQuery(pkce().challenge));
    Object.defineProperty(authorizeRequest, "method", { get() { throw new Error(raw); } });
    const cases = [
      new Request(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`),
      new Request(`${ORIGIN}/.well-known/oauth-authorization-server`),
      authorizeRequest,
    ];
    for (const request of cases) {
      const response = await handleOAuth(request, env);
      assert.equal(response.status, 500);
      assert.deepEqual(await response.json(), { error: "internal_error" });
    }
    authorizationFetch.mock.mockImplementation(async () => { throw new Error(raw); });
    const response = await handleOAuth(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "synthetic-refresh",
      client_id: CHATGPT_CLIENT_ID,
    }).toString()), env);
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: "internal_error" });
    assertClean(logs.join("\n"), [raw]);
  });

  it("refuses authorize requests before any library call, fetch, or write", async () => {
    mock.method(globalThis, "fetch", (input: unknown) => {
      fetches.push(input instanceof Request ? input.url : String(input));
      return Response.json(CIMD);
    });
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    const { challenge } = pkce();
    const grok = `admrn_gb_${"a".repeat(43)}`;
    const cases: [string, Request][] = [
      ["other client", new Request(authorizeQuery(challenge, { client_id: "https://evil.example/client.json" }))],
      ["other redirect", new Request(authorizeQuery(challenge, { redirect_uri: "https://evil.example/callback" }))],
      ["implicit", new Request(authorizeQuery(challenge, { response_type: "token" }))],
      ["plain pkce", new Request(authorizeQuery(challenge, { code_challenge_method: "plain" }))],
      ["other resource", new Request(authorizeQuery(challenge, { resource: "https://evil.example/mcp" }))],
      ["code in url", new Request(`${ORIGIN}/authorize?connect_code=${CODE}&client_id=${CHATGPT_CLIENT_ID}`)],
      ["grok token", new Request(authorizeQuery(challenge, { state: grok }))],
      ["bad scope", new Request(authorizeQuery(challenge, { scope: "bad\"scope" }))],
      ["put", new Request(`${ORIGIN}/authorize`, { method: "PUT" })],
    ];
    for (const [name, request] of cases) {
      const { d1, kv, env } = fresh();
      const before = d1.writeBatches;
      const response = await routeRequest(request, env);
      assert.equal(response.status >= 400, true, name);
      const html = await response.text();
      assert.match(html, /Connection failed/, name);
      assertClean(html, [CODE, grok, EMAIL, "evil.example/callback"]);
      assert.equal(d1.writeBatches, before, name);
      assert.equal(kv.writes, 0, name);
      assert.equal(d1.sessions.length, 0, name);
    }
    const { d1, kv, env } = fresh(false);
    const unlocked = await routeRequest(new Request(authorizeQuery(challenge)), env);
    assert.equal(unlocked.status, 400);
    assert.match(await unlocked.text(), /Connection failed/);
    assert.equal(d1.writeBatches, 0);
    assert.equal(kv.writes, 0);
    assert.equal(fetches.length, 0);
    assertClean(logs.join("\n"), [CODE, grok, EMAIL]);
  });

  it("returns the same authorize page when state contains the owner email", async () => {
    mock.method(globalThis, "fetch", () => { throw new Error("must not fetch"); });
    const { challenge } = pkce();
    const disclosed = fresh();
    const email = await routeRequest(new Request(authorizeQuery(challenge, { state: `prefix-${EMAIL}` })), disclosed.env);
    const plain = fresh();
    const random = await routeRequest(new Request(authorizeQuery(challenge, { state: "synthetic-state" })), plain.env);
    assert.equal(email.status, random.status);
    assert.equal(email.status, 200);
    const emailBody = await email.text();
    const randomBody = await random.text();
    assert.equal(emailBody.includes(EMAIL), false);
    assert.equal(randomBody.includes(EMAIL), false);
    assert.match(emailBody, /<form method="post" action="\/authorize">/);
    assert.match(randomBody, /<form method="post" action="\/authorize">/);
    assert.match(emailBody, /name="state" value="prefix-synthetic-owner&#64;example\.invalid"/);
    assert.equal(disclosed.d1.writeBatches, 0);
    assert.equal(plain.d1.writeBatches, 0);
  });

  it("refuses a connect code echoed back to the browser", async () => {
    mock.method(globalThis, "fetch", () => { throw new Error("must not fetch"); });
    const { challenge } = pkce();
    const coded = fresh();
    const code = await routeRequest(new Request(authorizeQuery(challenge, { state: CODE })), coded.env);
    assert.equal(code.status, 400);
    assert.equal((await code.text()).includes(CODE), false);
    assert.equal(coded.kv.writes, 0);
    const posted = fresh();
    const echoed = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge, { state: CODE })), posted.env);
    assert.equal(echoed.status, 400);
    assert.equal((await echoed.text()).includes(CODE), false);
    assert.equal(posted.kv.writes, 0);
    assert.equal(posted.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, null);
  });

  it("allows Origin null on the consent route only with Sec-Fetch-Site same-origin", () => {
    // [name, headers, POST /authorize rule, strict rule used by POST /owner/claim]
    const cases: [string, Record<string, string>, boolean, boolean][] = [
      ["null + same-origin", { Origin: "null", "Sec-Fetch-Site": "same-origin" }, true, false],
      ["null alone", { Origin: "null" }, false, false],
      ["null + cross-site", { Origin: "null", "Sec-Fetch-Site": "cross-site" }, false, false],
      ["null + same-site", { Origin: "null", "Sec-Fetch-Site": "same-site" }, false, false],
      ["null + none", { Origin: "null", "Sec-Fetch-Site": "none" }, false, false],
      ["bridge origin", { Origin: ORIGIN }, true, true],
      ["bridge origin + same-origin", { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" }, true, true],
      ["foreign origin + same-origin", { Origin: "https://evil.example", "Sec-Fetch-Site": "same-origin" }, false, false],
      ["foreign origin + cross-site", { Origin: "https://evil.example", "Sec-Fetch-Site": "cross-site" }, false, false],
      ["same-origin, no Origin", { "Sec-Fetch-Site": "same-origin" }, true, true],
      ["same-site, no Origin", { "Sec-Fetch-Site": "same-site" }, false, false],
      ["cross-site, no Origin", { "Sec-Fetch-Site": "cross-site" }, false, false],
      ["none, no Origin", { "Sec-Fetch-Site": "none" }, false, false],
      ["neither header", {}, true, true],
    ];
    for (const [name, headers, consent, strict] of cases) {
      const request = new Request(`${ORIGIN}/authorize`, { method: "POST", headers });
      assert.equal(consentPostAllowed(request, ORIGIN), consent, `consent: ${name}`);
      assert.equal(sameOriginPostAllowed(request, ORIGIN), strict, `strict: ${name}`);
    }
  });

  it("connects on allowed consent Origin pairs and refuses null or none pairs without a write", async () => {
    mock.method(globalThis, "fetch", async (input: unknown) => {
      const url = input instanceof Request ? input.url : String(input);
      fetches.push(url);
      if (url !== CHATGPT_CLIENT_ID) throw new Error(`unexpected fetch ${url}`);
      return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
    });
    mock.method(console, "log", () => {});
    mock.method(console, "error", () => {});
    const { challenge } = pkce();
    const refused: [string, Record<string, string>][] = [
      ["null alone", { Origin: "null" }],
      ["null + cross-site", { Origin: "null", "Sec-Fetch-Site": "cross-site" }],
      ["null + same-site", { Origin: "null", "Sec-Fetch-Site": "same-site" }],
      ["null + none", { Origin: "null", "Sec-Fetch-Site": "none" }],
      ["foreign origin + same-origin", { Origin: "https://evil.example", "Sec-Fetch-Site": "same-origin" }],
      ["none, no Origin", { "Sec-Fetch-Site": "none" }],
    ];
    for (const [name, headers] of refused) {
      const { d1, kv, env } = fresh();
      const response = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge), headers), env);
      assert.equal(response.status, 403, name);
      assert.equal(response.headers.get("Referrer-Policy"), "same-origin", name);
      assert.match(await response.text(), /Connection failed/, name);
      assert.equal(d1.writeBatches, 0, name);
      assert.equal(d1.sessions.length, 0, name);
      assert.equal(kv.writes, 0, name);
      assert.equal(d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, null, name);
    }
    assert.deepEqual(fetches, []);

    const allowed: [string, Record<string, string>][] = [
      ["null + same-origin", { Origin: "null", "Sec-Fetch-Site": "same-origin" }],
      ["ordinary same-origin", { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" }],
      ["neither header", {}],
    ];
    for (const [name, headers] of allowed) {
      const { d1, kv, env } = fresh();
      const connected = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge), headers), env);
      assert.equal(connected.status, 303, name);
      assert.equal(connected.headers.get("Referrer-Policy"), "same-origin", name);
      const location = connected.headers.get("Location");
      assert.ok(location, name);
      const target = new URL(location);
      assert.equal(`${target.origin}${target.pathname}`, CHATGPT_REDIRECT, name);
      assert.ok(target.searchParams.get("code"), name);
      assert.notEqual(d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, null, name);
      assert.ok(kv.writes > 0, name);
    }
  });

  it("connects Dot once, exchanges the code, and keeps secrets out of storage and logs", async () => {
    mock.method(globalThis, "fetch", async (input: unknown) => {
      const url = input instanceof Request ? input.url : String(input);
      fetches.push(url);
      if (url !== CHATGPT_CLIENT_ID) throw new Error(`unexpected fetch ${url}`);
      return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
    });
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    const issued = await issue();
    const validation = await validateDotAccessToken(issued.env, issued.access);
    assert.ok(validation && typeof validation === "object");
    const token = validation as { userId: string; clientId: string; audience: string; props: { credential_id: string } };
    assert.equal(token.userId, "dot");
    assert.equal(token.clientId, CHATGPT_CLIENT_ID);
    assert.equal(token.audience, RESOURCE);
    assert.match(token.props.credential_id, /^credential_/);
    const row = issued.d1.sqlite.prepare(
      "SELECT participant, owner_claimed_at, revoked_at FROM participant_credential WHERE id = ?",
    ).get(token.props.credential_id) as { participant: string; owner_claimed_at: string; revoked_at: string | null };
    assert.equal(row.participant, "dot");
    assert.equal(row.owner_claimed_at, OWNER);
    assert.equal(row.revoked_at, null);
    assert.notEqual(issued.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential WHERE id = 'old-dot'").get()?.revoked_at, null);
    assert.notEqual(issued.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, null);
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").get()?.n, 1);
    const stored = dumpedKv(issued.kv);
    assertClean(stored, [EMAIL, CODE, OWNER, issued.access, issued.refresh, issued.verifier]);
    assert.equal(fetches.every((url) => url === CHATGPT_CLIENT_ID), true);
    assertClean(logs.join("\n"), [EMAIL, CODE, issued.access, issued.refresh, issued.verifier]);

    const again = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(pkce().challenge)), issued.env);
    assert.equal(again.status, 400);
    assert.equal((await again.text()).includes(CODE), false);
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").get()?.n, 1);
  });

  it("rejects a wrong, expired, used, or stale connect code without a grant", async () => {
    mock.method(globalThis, "fetch", async () => Response.json(CIMD, { headers: { "Cache-Control": "no-store" } }));
    const { challenge } = pkce();
    const wrong = fresh();
    const wrongBody = formBody(challenge, { connect_code: "d".repeat(43) });
    const rejected = await routeRequest(postForm(`${ORIGIN}/authorize`, wrongBody), wrong.env);
    assert.equal(rejected.status, 400);
    assert.equal(wrong.kv.writes, 0);
    assert.equal(wrong.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential WHERE id = 'old-dot'").get()?.revoked_at, null);

    const expired = fresh();
    expired.d1.sqlite.prepare("UPDATE connect_code SET expires_at = ?").run("2000-01-01T00:00:00.000Z");
    assert.equal((await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge)), expired.env)).status, 400);
    assert.equal(expired.kv.writes, 0);

    const used = fresh();
    used.d1.sqlite.prepare("UPDATE connect_code SET used_at = ?").run(OWNER);
    assert.equal((await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge)), used.env)).status, 400);
    assert.equal(used.kv.writes, 0);

    const stale = fresh();
    stale.d1.sqlite.prepare("UPDATE connect_code SET owner_claimed_at = ?").run("1999-01-01T00:00:00.000Z");
    assert.equal((await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge)), stale.env)).status, 400);
    assert.equal(stale.kv.writes, 0);

    const inUrl = fresh();
    const posted = await routeRequest(postForm(`${ORIGIN}/authorize?connect_code=${CODE}`, formBody(challenge)), inUrl.env);
    assert.equal(posted.status, 400);
    assert.equal((await posted.text()).includes(CODE), false);
    assert.equal(inUrl.d1.sessions.length, 0);
    assert.equal(inUrl.kv.writes, 0);
  });

  it("replays the same Connect submit without a second grant", async () => {
    mock.method(globalThis, "fetch", async () => Response.json(CIMD, { headers: { "Cache-Control": "no-store" } }));
    const { challenge } = pkce();
    const { env, d1 } = fresh();
    const body = formBody(challenge);
    const first = await routeRequest(postForm(`${ORIGIN}/authorize`, body), env);
    assert.equal(first.status, 303);
    const location = first.headers.get("Location");
    assert.ok(location);
    const second = await routeRequest(postForm(`${ORIGIN}/authorize`, body), env);
    assert.equal(second.status, 303);
    assert.equal(second.headers.get("Location"), location);
    assert.equal(second.headers.get("Cache-Control"), "no-store");
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").get()?.n, 1);
    const used = d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at;
    assert.equal(typeof used, "string");
    const other = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(pkce().challenge)), env);
    assert.equal(other.status, 400);
    assert.equal(other.headers.get("Location"), null);
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").get()?.n, 1);
  });

  it("returns one redirect when two Connect submits race", async () => {
    mock.method(globalThis, "fetch", async () => Response.json(CIMD, { headers: { "Cache-Control": "no-store" } }));
    const { challenge } = pkce();
    const { env, d1 } = fresh();
    const body = formBody(challenge);
    const responses = await Promise.all([
      routeRequest(postForm(`${ORIGIN}/authorize`, body), env),
      routeRequest(postForm(`${ORIGIN}/authorize`, body), env),
    ]);
    assert.deepEqual(responses.map((response) => response.status), [303, 303]);
    const location = responses[0]?.headers.get("Location");
    assert.ok(location);
    assert.equal(responses[1]?.headers.get("Location"), location);
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").get()?.n, 1);
  });

  it("settles two concurrent spends as one credential", async () => {
    mock.method(globalThis, "fetch", async () => Response.json(CIMD, { headers: { "Cache-Control": "no-store" } }));
    const { d1, env } = fresh();
    d1.holdWritesUntil(2);
    const body = formBody(pkce().challenge);
    const responses = await Promise.all([
      routeRequest(postForm(`${ORIGIN}/authorize`, body), env),
      routeRequest(postForm(`${ORIGIN}/authorize`, formBody(pkce().challenge)), env),
    ]);
    assert.deepEqual(responses.map((response) => response.status).sort(), [303, 400]);
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").get()?.n, 1);
  });

  it("refuses token requests that are missing, malformed, or for another client", async () => {
    mock.method(globalThis, "fetch", (input: unknown) => {
      fetches.push(input instanceof Request ? input.url : String(input));
      return Response.json(CIMD);
    });
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    const { env } = fresh();
    const grok = `admrn_gb_${"b".repeat(43)}`;
    const evil = "https://evil.example/client.json";
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: evil })).toString("base64url");
    const cases: [string, Request, number, string][] = [
      ["get", new Request(`${ORIGIN}/token`), 405, "invalid_request"],
      ["json", new Request(`${ORIGIN}/token`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }), 415, "invalid_request"],
      ["missing", postForm(`${ORIGIN}/token`, `client_id=${encodeURIComponent(CHATGPT_CLIENT_ID)}`), 400, "invalid_request"],
      ["password", postForm(`${ORIGIN}/token`, `grant_type=password&client_id=${encodeURIComponent(CHATGPT_CLIENT_ID)}`), 400, "unsupported_grant_type"],
      ["other client", postForm(`${ORIGIN}/token`, `grant_type=authorization_code&client_id=${encodeURIComponent(evil)}`), 401, "invalid_client"],
      ["other assertion", postForm(`${ORIGIN}/token`, `client_assertion=${header}.${payload}.sig&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`), 401, "invalid_client"],
      ["bad scope", postForm(`${ORIGIN}/token`, `grant_type=refresh_token&refresh_token=synthetic&client_id=${encodeURIComponent(CHATGPT_CLIENT_ID)}&scope=${encodeURIComponent("bad\"scope")}`), 400, "invalid_scope"],
      ["authorization header", new Request(`${ORIGIN}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Bearer ${grok}` }, body: "grant_type=refresh_token" }), 400, "invalid_request"],
      ["grok field", postForm(`${ORIGIN}/token`, `grant_type=refresh_token&refresh_token=${grok}&client_id=${encodeURIComponent(CHATGPT_CLIENT_ID)}`), 400, "invalid_request"],
      ["oversize", postForm(`${ORIGIN}/token`, `x=${"a".repeat(16 * 1024)}`), 413, "invalid_request"],
      ["binary", new Request(`${ORIGIN}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new Uint8Array([0xff]) }), 400, "invalid_request"],
    ];
    for (const [name, request, status, error] of cases) {
      const response = await routeRequest(request, env);
      assert.equal(response.status, status, name);
      const body = await response.json() as { error?: string };
      assert.equal(body.error, error, name);
      assert.equal(JSON.stringify(body).includes(grok), false, name);
      assert.equal(JSON.stringify(body).includes(evil), false, name);
    }
    assert.deepEqual(fetches, []);
    assertClean(logs.join("\n"), [grok, evil]);
    const allow = await routeRequest(new Request(`${ORIGIN}/token`), env);
    assert.equal(allow.headers.get("Allow"), "POST");
  });

  it("allows omitted or configured refresh resources and refuses wrong or duplicate resources without rotation", async () => {
    mock.method(globalThis, "fetch", async () => Response.json(CIMD, { headers: { "Cache-Control": "no-store" } }));
    mock.method(console, "log", () => {});
    mock.method(console, "error", () => {});
    const cases: [string, string[], number][] = [
      ["omitted", [], 200],
      ["configured", [RESOURCE], 200],
      ["wrong", ["https://other.example/mcp"], 400],
      ["duplicate", [RESOURCE, RESOURCE], 400],
    ];
    for (const [name, resources, expected] of cases) {
      const issued = await issue();
      const params = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: issued.refresh,
        client_id: CHATGPT_CLIENT_ID,
      });
      for (const resource of resources) params.append("resource", resource);
      const stored = dumpedKv(issued.kv);
      const writes = issued.kv.writes;
      const response = await routeRequest(postForm(`${ORIGIN}/token`, params.toString()), issued.env);
      assert.equal(response.status, expected, name);
      if (expected === 200) {
        const body = await response.json() as { access_token?: string; resource?: string };
        assert.equal(body.resource, RESOURCE, name);
        const validated = await validateDotAccessToken(issued.env, body.access_token ?? "") as { audience?: string } | null;
        assert.equal(validated?.audience, RESOURCE, name);
      } else {
        assert.deepEqual(await response.json(), { error: "invalid_request" }, name);
        assert.equal(dumpedKv(issued.kv), stored, name);
        assert.equal(issued.kv.writes, writes, name);
        params.delete("resource");
        params.set("resource", RESOURCE);
        const recovered = await routeRequest(postForm(`${ORIGIN}/token`, params.toString()), issued.env);
        assert.equal(recovered.status, 200, name);
      }
    }
  });

  it("requires exactly the configured resource on code exchange without consuming refused codes", async () => {
    mock.method(globalThis, "fetch", async () => Response.json(CIMD, { headers: { "Cache-Control": "no-store" } }));
    mock.method(console, "log", () => {});
    mock.method(console, "error", () => {});
    const cases: [string, string[], number][] = [
      ["omitted", [], 400],
      ["configured", [RESOURCE], 200],
      ["wrong", ["https://other.example/mcp"], 400],
      ["duplicate", [RESOURCE, RESOURCE], 400],
    ];
    for (const [name, resources, expected] of cases) {
      const { verifier, challenge } = pkce();
      const { env, kv } = fresh();
      const consent = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge)), env);
      assert.equal(consent.status, 303, name);
      const location = consent.headers.get("Location");
      assert.ok(location, name);
      const code = new URL(location).searchParams.get("code");
      assert.ok(code, name);
      const params = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: CHATGPT_CLIENT_ID,
        redirect_uri: CHATGPT_REDIRECT,
        code_verifier: verifier,
      });
      for (const resource of resources) params.append("resource", resource);
      const stored = dumpedKv(kv);
      const writes = kv.writes;
      const response = await routeRequest(postForm(`${ORIGIN}/token`, params.toString()), env);
      assert.equal(response.status, expected, name);
      if (expected === 200) {
        const body = await response.json() as { access_token?: string; resource?: string };
        assert.equal(body.resource, RESOURCE, name);
        const validated = await validateDotAccessToken(env, body.access_token ?? "") as { audience?: string } | null;
        assert.equal(validated?.audience, RESOURCE, name);
      } else {
        assert.deepEqual(await response.json(), { error: "invalid_request" }, name);
        assert.equal(dumpedKv(kv), stored, name);
        assert.equal(kv.writes, writes, name);
        params.delete("resource");
        params.set("resource", RESOURCE);
        const recovered = await routeRequest(postForm(`${ORIGIN}/token`, params.toString()), env);
        assert.equal(recovered.status, 200, name);
      }
    }
  });

  it("authenticates refresh clients and tokens before comparing their requested scope", async () => {
    mock.method(globalThis, "fetch", async (input: unknown) => {
      const clientId = input instanceof Request ? input.url : String(input);
      const claude = clientId === CLAUDE_CLIENT_ID;
      return Response.json({ ...CIMD, client_id: clientId, ...(claude ? { redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] } : {}) }, {
        headers: { "Cache-Control": "no-store" },
      });
    });
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    const issued = await issue("notes extra");
    const forged = `${issued.refresh.slice(0, issued.refresh.lastIndexOf(":") + 1)}${"x".repeat(43)}`;
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: CHATGPT_CLIENT_ID })).toString("base64url");
    const assertion = `${header}.${payload}.sig`;
    const stored = dumpedKv(issued.kv);
    const writes = issued.kv.writes;
    const cases: [string, string, Record<string, string>, string][] = [
      ["wrong client current", issued.refresh, { client_id: CLAUDE_CLIENT_ID }, "invalid_grant"],
      ["wrong client forged", forged, { client_id: CLAUDE_CLIENT_ID }, "invalid_grant"],
      ["forged token", forged, { client_id: CHATGPT_CLIENT_ID }, "invalid_grant"],
      ["invalid assertion current", issued.refresh, {
        client_id: CHATGPT_CLIENT_ID,
        client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }, "invalid_client"],
      ["invalid assertion forged", forged, {
        client_id: CHATGPT_CLIENT_ID,
        client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }, "invalid_client"],
    ];
    for (const [name, refresh, client, error] of cases) {
      const outcomes: { status: number; body: unknown }[] = [];
      for (const scope of ["notes extra", "notes", "ungranted"]) {
        const response = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
          grant_type: "refresh_token", refresh_token: refresh, scope, ...client,
        }).toString()), issued.env);
        outcomes.push({ status: response.status, body: await response.json() });
        assert.equal(dumpedKv(issued.kv), stored, `${name}: ${scope}`);
        assert.equal(issued.kv.writes, writes, `${name}: ${scope}`);
      }
      assert.deepEqual(outcomes.map(({ body }) => body), [{ error }, { error }, { error }], name);
      assert.ok(outcomes.every(({ status }) => status === outcomes[0]?.status), name);
    }
    assertClean(logs.join("\n"), [issued.refresh, forged, assertion]);
  });

  it("rejects a bad code, a wrong scope, a revoked token, and the wrong audience", async () => {
    mock.method(globalThis, "fetch", async (input: unknown) => {
      const url = input instanceof Request ? input.url : String(input);
      fetches.push(url);
      if (url !== CHATGPT_CLIENT_ID) throw new Error(`unexpected fetch ${url}`);
      return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
    });
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    const advance = steppedClock();
    const { verifier, challenge } = pkce();
    const { env } = fresh();
    const badCode = "not-a-code";
    const bad = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "authorization_code",
      code: badCode,
      redirect_uri: CHATGPT_REDIRECT,
      client_id: CHATGPT_CLIENT_ID,
      code_verifier: verifier,
      resource: RESOURCE,
    }).toString()), env);
    assert.equal(bad.status, 400);
    assert.deepEqual(await bad.json(), { error: "invalid_grant" });
    assert.equal(fetches.every((url) => url === CHATGPT_CLIENT_ID), true);

    const issued = await issue();
    const upscope = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: issued.refresh,
      client_id: CHATGPT_CLIENT_ID,
      scope: "notes",
    }).toString()), issued.env);
    assert.equal(upscope.status, 400);
    assert.deepEqual(await upscope.json(), { error: "invalid_scope" });
    assert.ok(await validateDotAccessToken(issued.env, issued.access));

    const scoped = await issue("notes extra");
    const grants = [...scoped.kv.records.entries()].filter(([key]) => key.startsWith("grant:"));
    assert.equal(grants.length, 1);
    const grantKey = grants[0]?.[0] ?? "";
    const savedGrant = grants[0]?.[1].value ?? "";
    assert.deepEqual((JSON.parse(savedGrant) as { scope?: unknown }).scope, ["notes", "extra"]);
    const writes = scoped.kv.writes;
    for (const scope of ["", "notes", "extra notes", "notes extra extra"]) {
      const narrowed = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: scoped.refresh,
        client_id: CHATGPT_CLIENT_ID,
        scope,
      }).toString()), scoped.env);
      assert.equal(narrowed.status, 400, scope);
      assert.deepEqual(await narrowed.json(), { error: "invalid_scope" }, scope);
      assert.equal(scoped.kv.records.get(grantKey)?.value, savedGrant, scope);
      assert.equal(scoped.kv.writes, writes, scope);
    }
    const missingGrant = `dot:${"a".repeat(16)}:${"b".repeat(32)}`;
    const missing = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: missingGrant,
      client_id: CHATGPT_CLIENT_ID,
      scope: "notes",
    }).toString()), scoped.env);
    assert.equal(missing.status, 400);
    assert.deepEqual(await missing.json(), { error: "invalid_grant" });
    const refreshed = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: scoped.refresh,
      client_id: CHATGPT_CLIENT_ID,
    }).toString()), scoped.env);
    assert.equal(refreshed.status, 200);
    const refreshedBody = await refreshed.json() as { access_token?: string; refresh_token?: string; scope?: string };
    assert.equal(refreshedBody.scope, "notes extra");
    assert.equal(typeof refreshedBody.access_token, "string");
    assert.notEqual(refreshedBody.refresh_token, scoped.refresh);
    assert.ok(await validateDotAccessToken(scoped.env, refreshedBody.access_token ?? ""));
    advance(BUDGET_MS);
    const exact = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshedBody.refresh_token ?? "",
      client_id: CHATGPT_CLIENT_ID,
      scope: "notes extra",
    }).toString()), scoped.env);
    assert.equal(exact.status, 200);
    const exactBody = await exact.json() as { scope?: string; access_token?: string; refresh_token?: string };
    assert.equal(exactBody.scope, "notes extra");
    scoped.kv.get = () => Promise.reject(new Error("synthetic kv outage"));
    advance(BUDGET_MS);
    const down = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: exactBody.refresh_token ?? "",
      client_id: CHATGPT_CLIENT_ID,
      scope: "notes",
    }).toString()), scoped.env);
    assert.equal(down.status, 503);
    assert.equal(down.headers.get("Retry-After"), "1");
    const downBody = await down.json() as { error?: string };
    assert.deepEqual(downBody, { error: "unavailable" });
    assert.equal(JSON.stringify(downBody).includes("synthetic kv outage"), false);

    const revoked = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      token: issued.access,
      token_type_hint: "access_token",
      client_id: CHATGPT_CLIENT_ID,
    }).toString()), issued.env);
    assert.equal(revoked.status, 200);
    assert.equal((await revoked.text()).includes(issued.access), false);
    assert.equal(await validateDotAccessToken(issued.env, issued.access), null);
    assert.equal(await validateDotAccessToken(issued.env, "not-a-token"), null);

    const second = await issue();
    for (const row of second.kv.records.values()) {
      if (!row.value.includes("\"audience\"")) continue;
      const data = JSON.parse(row.value) as { audience?: string; expiresAt?: number };
      if (data.audience === RESOURCE) data.audience = "https://other.example/mcp";
      row.value = JSON.stringify(data);
    }
    assert.equal(await validateDotAccessToken(second.env, second.access), null);
    for (const row of second.kv.records.values()) {
      const data = JSON.parse(row.value) as { audience?: string; expiresAt?: number };
      if (data.audience) {
        data.audience = RESOURCE;
        data.expiresAt = Math.floor(Date.now() / 1000) - 5;
        row.value = JSON.stringify(data);
      }
    }
    assert.equal(await validateDotAccessToken(second.env, second.access), null);
    assertClean(logs.join("\n"), [
      badCode, issued.access, issued.refresh, verifier, challenge,
      scoped.access, scoped.refresh, missingGrant,
      refreshedBody.access_token ?? "", refreshedBody.refresh_token ?? "",
      exactBody.access_token ?? "", exactBody.refresh_token ?? "",
    ].filter((secret) => secret.length > 0));
  });

  it("rejects repeated ungranted-scope refreshes with no D1 writes, including before the first rotation", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const attempts = 8;
    const rejectedScopes = ["ungranted", "notes", ""];
    const issued = await issue("notes extra");
    assert.equal(family(issued.d1).previous_until_ms, null);
    assert.equal(family(issued.d1).pending_id, null);
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const bodies: string[] = [];
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const scope = rejectedScopes[attempt % rejectedScopes.length] ?? "ungranted";
      const response = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: issued.refresh,
        client_id: CHATGPT_CLIENT_ID,
        scope,
      }).toString()), issued.env);
      assert.equal(response.status, 400, scope);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_scope" }, scope);
    }
    assert.equal(rowWrites(issued.d1), writes, "rejected scopes must not write D1");
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal(family(issued.d1).previous_until_ms, null);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).current_sha256, before.current_sha256);
    assert.ok(dumpedKv(issued.kv) === stored, "rejected scopes must not write provider KV");
    const first = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.ok(typeof family(issued.d1).previous_until_ms === "number");
    assert.equal((await ping(issued.env, first.access_token)).status, 200);

    advance(BUDGET_MS);
    const eligible = family(issued.d1);
    assert.ok(typeof eligible.previous_until_ms === "number");
    const laterWrites = rowWrites(issued.d1);
    const laterStored = dumpedKv(issued.kv);
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const scope = rejectedScopes[attempt % rejectedScopes.length] ?? "ungranted";
      const response = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: first.refresh_token,
        client_id: CHATGPT_CLIENT_ID,
        scope,
      }).toString()), issued.env);
      assert.equal(response.status, 400, scope);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_scope" }, scope);
    }
    assert.equal(rowWrites(issued.d1), laterWrites, "rejected scopes after the budget interval must not write D1");
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal(family(issued.d1).previous_until_ms, eligible.previous_until_ms);
    assert.equal(family(issued.d1).current_sha256, eligible.current_sha256);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.ok(dumpedKv(issued.kv) === laterStored);
    const continued = await rotated(issued.env, first.refresh_token);
    assert.equal((await ping(issued.env, continued.access_token)).status, 200);

    // The successor is inside the rotation budget. Advance to the boundary so
    // these rejections are eligible admissions, where a claim would have written.
    advance(BUDGET_MS);
    const assertion = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ iss: CHATGPT_CLIENT_ID })).toString("base64url")}.sig`;
    const authWrites = rowWrites(issued.d1);
    const authBefore = family(issued.d1);
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const response = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: continued.refresh_token,
        client_id: CHATGPT_CLIENT_ID,
        client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString()), issued.env);
      assert.equal(response.status, 401);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_client" });
    }
    assert.equal(rowWrites(issued.d1), authWrites, "rejected client authentication must not write D1");
    assert.ok(isDeepStrictEqual(family(issued.d1), authBefore));
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const response = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
        token: continued.refresh_token,
        token_type_hint: "refresh_token",
        client_id: CHATGPT_CLIENT_ID,
        client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString()), issued.env);
      assert.equal(response.status, 401);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_client" });
    }
    assert.equal(rowWrites(issued.d1), authWrites, "rejected revocation authentication must not write D1");
    assert.ok(isDeepStrictEqual(family(issued.d1), authBefore));
    const afterAuth = await rotated(issued.env, continued.refresh_token);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal((await ping(issued.env, afterAuth.access_token)).status, 200);

    advance(BUDGET_MS);
    const grant = [...issued.kv.records.entries()].find(([key]) => key.startsWith("grant:"));
    assert.ok(grant);
    const savedGrant = grant[1].value;
    const expiredGrant = JSON.parse(savedGrant) as { expiresAt?: number };
    expiredGrant.expiresAt = Math.floor(Date.now() / 1000) - 120;
    grant[1].value = JSON.stringify(expiredGrant);
    const expiryWrites = rowWrites(issued.d1);
    const expiryBefore = family(issued.d1);
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const response = await refreshGrant(issued.env, afterAuth.refresh_token);
      assert.equal(response.status, 400);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_grant" });
    }
    assert.equal(rowWrites(issued.d1), expiryWrites, "an expired refresh must not write D1");
    assert.ok(isDeepStrictEqual(family(issued.d1), expiryBefore));
    grant[1].value = savedGrant;
    const restored = await rotated(issued.env, afterAuth.refresh_token);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal((await ping(issued.env, restored.access_token)).status, 200);
    assertFamilyLogsClean([
      issued.access, issued.refresh, first.access_token, first.refresh_token,
      continued.access_token, continued.refresh_token, afterAuth.access_token, afterAuth.refresh_token,
      restored.access_token, restored.refresh_token, assertion,
    ], bodies.join("\n"));
  });

  it("rejects repeated token-endpoint parameters on an eligible refresh with no D1 writes", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    assert.equal(family(issued.d1).previous_until_ms, null);
    assert.equal(family(issued.d1).pending_id, null);
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    // code, code_verifier, and token are legal field names. Repeating any of
    // them used to pass prefilter and claim an eligible refresh before the
    // provider rejected the body.
    const fields = ["code", "code_verifier", "token", "code"];
    const bodies: string[] = [];
    for (const field of fields) {
      const response = await routeRequest(postForm(`${ORIGIN}/token`, withRepeatedField({
        grant_type: "refresh_token",
        refresh_token: issued.refresh,
        client_id: CHATGPT_CLIENT_ID,
      }, field)), issued.env);
      assert.equal(response.status, 400, field);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_request" }, field);
    }
    assert.equal(rowWrites(issued.d1), writes, "repeated parameters must not write D1");
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal(family(issued.d1).previous_until_ms, null);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).current_sha256, before.current_sha256);
    assert.ok(dumpedKv(issued.kv) === stored, "repeated parameters must not write provider KV");
    const rotatedToken = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal((await ping(issued.env, rotatedToken.access_token)).status, 200);
    assertFamilyLogsClean([
      issued.access, issued.refresh, rotatedToken.access_token, rotatedToken.refresh_token,
    ], bodies.join("\n"));
  });

  it("rejects repeated parameters on an eligible refresh revocation with no D1 writes", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    const before = family(issued.d1);
    assert.equal(before.previous_until_ms, null);
    assert.equal(before.pending_id, null);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const bodies: string[] = [];
    for (const field of ["code", "code_verifier", "refresh_token", "code"]) {
      const response = await routeRequest(postForm(`${ORIGIN}/token`, withRepeatedField({
        token: issued.refresh,
        token_type_hint: "refresh_token",
        client_id: CHATGPT_CLIENT_ID,
      }, field)), issued.env);
      assert.equal(response.status, 400, field);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_request" }, field);
    }
    assert.equal(rowWrites(issued.d1), writes, "repeated revocation parameters must not write D1");
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.ok(dumpedKv(issued.kv) === stored, "repeated revocation parameters must not write provider KV");
    const refreshed = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal((await ping(issued.env, refreshed.access_token)).status, 200);
    assertFamilyLogsClean([
      issued.access, issued.refresh, refreshed.access_token, refreshed.refresh_token,
    ], bodies.join("\n"));
  });

  it("does not claim when the provider rejects a refresh before reading the grant", async () => {
    installFamilyMocks();
    mock.method(console, "warn", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    const issued = await issue("notes extra");
    const before = family(issued.d1);
    assert.equal(before.previous_until_ms, null);
    assert.equal(before.pending_id, null);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const bodies: string[] = [];
    const cimd = async () => Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
    mock.method(globalThis, "fetch", async () => {
      throw new Error("synthetic cimd failure");
    });
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const response = await refreshGrant(issued.env, issued.refresh);
      assert.equal(response.status, 401);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_client" });
      assert.equal(body.includes("synthetic cimd"), false);
    }
    assert.equal(rowWrites(issued.d1), writes, "a metadata failure must not claim or release the family");
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.ok(dumpedKv(issued.kv) === stored, "a metadata failure must not write provider KV");

    mock.method(globalThis, "fetch", async () => Response.json({
      ...CIMD,
      grant_types: [],
      response_types: [],
    }, { headers: { "Cache-Control": "no-store" } }));
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const response = await refreshGrant(issued.env, issued.refresh);
      assert.equal(response.status, 400);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "unauthorized_client" });
    }
    assert.equal(rowWrites(issued.d1), writes, "an unregistered grant must not claim or release the family");
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.ok(dumpedKv(issued.kv) === stored, "an unregistered grant must not write provider KV");

    mock.method(globalThis, "fetch", cimd);
    const refreshed = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal((await ping(issued.env, refreshed.access_token)).status, 200);

    mock.method(globalThis, "fetch", async () => {
      throw new Error("synthetic cimd failure");
    });
    const revocationWrites = rowWrites(issued.d1);
    const revocationBefore = family(issued.d1);
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const response = await revokeToken(issued.env, refreshed.refresh_token, "refresh_token");
      assert.equal(response.status, 401);
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "invalid_client" });
      assert.equal(body.includes("synthetic cimd"), false);
    }
    assert.equal(rowWrites(issued.d1), revocationWrites, "a revocation metadata failure must not write D1");
    assert.ok(isDeepStrictEqual(family(issued.d1), revocationBefore));
    mock.method(globalThis, "fetch", cimd);
    const resumed = await revokeToken(issued.env, refreshed.refresh_token, "refresh_token");
    assert.equal(resumed.status, 200);
    assertFamilyRevoked(issued.d1);
    assertFamilyLogsClean([
      issued.access, issued.refresh, refreshed.access_token, refreshed.refresh_token,
    ], bodies.join("\n"));
  });

  it("does not reopen an expired previous-token grace when a current-token admission is charged", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue("notes extra");
    const first = await rotated(issued.env, issued.refresh);
    const successor = tokenHash(first.refresh_token);
    // The previous token's one-use grace expires unused, then the budget elapses
    // so the current token can be admitted again.
    advance(BUDGET_MS);
    assert.equal(family(issued.d1).previous_used, 0);
    assert.equal(family(issued.d1).current_sha256, successor);
    assert.ok((family(issued.d1).previous_until_ms ?? 0) < Date.now());
    const originalGet = issued.kv.get.bind(issued.kv);
    let grantReads = 0;
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      if (key.startsWith("grant:") && options?.type === "json") {
        grantReads += 1;
        if (grantReads > 1) throw new Error("synthetic provider grant read failure");
      }
      return originalGet(key, options);
    };
    const failed = await refreshGrant(issued.env, first.refresh_token);
    assert.equal(failed.status, 503);
    assert.equal(failed.headers.get("Retry-After"), "1");
    const failedBody = await failed.text();
    assert.deepEqual(JSON.parse(failedBody), { error: "unavailable" });
    assert.equal(failedBody.includes("synthetic provider"), false);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).pending_id, null);
    issued.kv.get = originalGet;
    const ancestor = await refreshGrant(issued.env, issued.refresh);
    const ancestorBody = await ancestor.text();
    assert.equal(ancestor.status, 400);
    assert.deepEqual(JSON.parse(ancestorBody), { error: "invalid_grant" });
    assertFamilyRevoked(issued.d1);
    assert.equal(family(issued.d1).current_sha256, successor);
    assert.equal((await ping(issued.env, first.access_token)).status, 401);
    assertFamilyLogsClean([
      issued.access, issued.refresh, first.access_token, first.refresh_token,
    ], `${failedBody}\n${ancestorBody}`);
  });

  it("keeps a live grace retry when a current-token refresh fails inside the window", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    const first = await rotated(issued.env, issued.refresh);
    const until = family(issued.d1).previous_until_ms;
    assert.equal(family(issued.d1).previous_used, 0);
    assert.ok(typeof until === "number" && until >= Date.now());
    const originalGet = issued.kv.get.bind(issued.kv);
    let grantReads = 0;
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      if (key.startsWith("grant:") && options?.type === "json") {
        grantReads += 1;
        if (grantReads > 1) throw new Error("synthetic provider grant read failure");
      }
      return originalGet(key, options);
    };
    const failed = await refreshGrant(issued.env, first.refresh_token);
    assert.equal(failed.status, 503);
    assert.equal(failed.headers.get("Retry-After"), "900");
    const failedBody = await failed.text();
    assert.deepEqual(JSON.parse(failedBody), { error: "unavailable" });
    assert.equal(family(issued.d1).previous_until_ms, until);
    assert.equal(family(issued.d1).previous_used, 0);
    assert.equal(family(issued.d1).revoked_at, null);
    issued.kv.get = originalGet;
    const retry = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).previous_used, 1);
    assert.equal((await ping(issued.env, retry.access_token)).status, 200);
    assertFamilyLogsClean([
      issued.access, issued.refresh, first.access_token, first.refresh_token,
      retry.access_token, retry.refresh_token,
    ], failedBody);
  });

  it("leaves an open previous-token grace unchanged on a charged release", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    const first = await rotated(issued.env, issued.refresh);
    const before = family(issued.d1);
    const openUntil = before.previous_until_ms;
    assert.equal(before.previous_used, 0);
    assert.equal(before.previous_sha256, tokenHash(issued.refresh));
    assert.equal(before.current_sha256, tokenHash(first.refresh_token));
    assert.ok(typeof openUntil === "number" && openUntil >= Date.now());
    const row = issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_family").get();
    if (row === undefined || typeof row.id !== "string" || typeof row.credential_id !== "string"
      || typeof row.participant !== "string" || typeof row.client_id !== "string"
      || typeof row.grant_id !== "string" || typeof row.current_sha256 !== "string"
      || typeof row.position !== "number" || typeof row.previous_used !== "number") {
      throw new Error("missing family");
    }
    // Admission will not claim a current token while this grace is open, so the
    // open-window CASE in release() is reached by holding the claim directly.
    const exchange = new RefreshFamilyExchange(issued.d1.binding(), row.current_sha256, CHATGPT_CLIENT_ID);
    issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET pending_id = ? WHERE id = ?").run(exchange.nonce, row.id);
    exchange.held = {
      id: row.id,
      credential_id: row.credential_id,
      participant: row.participant,
      client_id: row.client_id,
      grant_id: row.grant_id,
      current_sha256: row.current_sha256,
      previous_sha256: typeof row.previous_sha256 === "string" ? row.previous_sha256 : null,
      previous_until_ms: typeof row.previous_until_ms === "number" ? row.previous_until_ms : null,
      previous_used: row.previous_used,
      position: row.position,
      pending_id: exchange.nonce,
      revoked_at: typeof row.revoked_at === "string" ? row.revoked_at : null,
      enabled: 1,
    };
    const preparedAt = issued.d1.prepared.length;
    const writes = rowWrites(issued.d1);
    await exchange.release();
    const charged = issued.d1.prepared.slice(preparedAt).filter((sql) => sql.includes("previous_until_ms = CASE"));
    assert.equal(charged.length, 1);
    assert.equal(charged[0]?.includes("previous_until_ms >= ?4"), true);
    assert.equal(rowWrites(issued.d1) - writes, 1);
    const after = family(issued.d1);
    assert.equal(after.previous_until_ms, openUntil);
    assert.equal(after.previous_used, 0);
    assert.equal(after.pending_id, null);
    assert.equal(after.current_sha256, before.current_sha256);
    assert.equal(after.revoked_at, null);
  });

  it("bounds D1 writes when the provider grant read throws after a successful pre-read", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue("notes extra");
    assert.equal(family(issued.d1).previous_until_ms, null);
    assert.equal(family(issued.d1).pending_id, null);
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const originalGet = issued.kv.get.bind(issued.kv);
    let grantReads = 0;
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      if (key.startsWith("grant:") && options?.type === "json") {
        grantReads += 1;
        if (grantReads > 1) throw new Error("synthetic provider grant read failure");
      }
      return originalGet(key, options);
    };
    const bodies: string[] = [];
    const statuses: number[] = [];
    const retries: Array<string | null> = [];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      grantReads = 0;
      const response = await refreshGrant(issued.env, issued.refresh);
      statuses.push(response.status);
      retries.push(response.headers.get("Retry-After"));
      const body = await response.text();
      bodies.push(body);
      assert.equal(body.includes("synthetic provider"), false);
    }
    const added = rowWrites(issued.d1) - writes;
    assert.ok(added <= 2, `provider grant read failures wrote ${added} D1 rows`);
    assert.deepEqual(statuses, [503, 503, 503, 503]);
    assert.equal(retries[0], "1");
    assert.ok(retries.slice(1).every((retry) => retry === "900"));
    assert.deepEqual(JSON.parse(bodies[0] ?? ""), { error: "unavailable" });
    assert.ok(bodies.slice(1).every((body) => JSON.parse(body).error === "unavailable"));
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).current_sha256, before.current_sha256);
    assert.equal(typeof family(issued.d1).previous_until_ms, "number");
    assert.ok(dumpedKv(issued.kv) === stored);
    assertUnavailableLog("oauth.unavailable", "storage_unavailable");
    assertUnavailableLog("oauth.unavailable", "refresh_budget");
    issued.kv.get = originalGet;
    advance(BUDGET_MS);
    const recovered = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal((await ping(issued.env, recovered.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, recovered.access_token, recovered.refresh_token], bodies.join("\n"));
  });

  it("does not claim a revocation when the provider grant read throws", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const originalGet = issued.kv.get.bind(issued.kv);
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      if (key.startsWith("grant:")) throw new Error("synthetic provider grant read failure");
      return originalGet(key, options);
    };
    const bodies: string[] = [];
    const responses: Response[] = [];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      responses.push(await revokeToken(issued.env, issued.refresh, "refresh_token"));
    }
    const added = rowWrites(issued.d1) - writes;
    assert.equal(added, 0, `revocation grant read failures wrote ${added} D1 rows`);
    for (const response of responses) {
      assert.equal(response.status, 503);
      assert.equal(response.headers.get("Retry-After"), "1");
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "unavailable" });
      assert.equal(body.includes("synthetic provider"), false);
    }
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.ok(dumpedKv(issued.kv) === stored);
    assertUnavailableLog("oauth.unavailable", "storage_unavailable");
    issued.kv.get = originalGet;
    const revoked = await revokeToken(issued.env, issued.refresh, "refresh_token");
    assert.equal(revoked.status, 200);
    assertFamilyRevoked(issued.d1);
    assertFamilyLogsClean([issued.access, issued.refresh], bodies.join("\n"));
  });

  it("releases a revocation claim when the confirming grant read throws", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const originalGet = issued.kv.get.bind(issued.kv);
    let grantReads = 0;
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      if (key.startsWith("grant:") && options?.type === "json") {
        grantReads += 1;
        if (grantReads === 2) throw new Error("synthetic confirming grant read failure");
      }
      return originalGet(key, options);
    };
    const response = await revokeToken(issued.env, issued.refresh, "refresh_token");
    assert.equal(grantReads, 2);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("Retry-After"), "1");
    const body = await response.text();
    assert.deepEqual(JSON.parse(body), { error: "unavailable" });
    assert.equal(body.includes("synthetic confirming"), false);
    assert.equal(rowWrites(issued.d1) - writes, 2);
    assert.equal(family(issued.d1).pending_id, null);
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.ok(dumpedKv(issued.kv) === stored);
    assertUnavailableLog("oauth.unavailable", "storage_unavailable");
    assertFamilyLogsClean([issued.access, issued.refresh], body);
  });

  it("releases a revocation claim when the confirming grant read returns a different grant", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const puts = issued.kv.writes;
    const originalGet = issued.kv.get.bind(issued.kv);
    const originalDelete = issued.kv.delete.bind(issued.kv);
    const originalList = issued.kv.list.bind(issued.kv);
    let grantReads = 0;
    let providerActions = 0;
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      const value = await originalGet(key, options);
      if (!key.startsWith("grant:") || options?.type !== "json" || !value || typeof value !== "object") return value;
      grantReads += 1;
      if (grantReads === 1) return value;
      return { ...value, refreshTokenId: "cd".repeat(32) };
    };
    issued.kv.delete = async (key: string) => {
      providerActions += 1;
      return originalDelete(key);
    };
    issued.kv.list = async (options?: { prefix?: string; limit?: number; cursor?: string }) => {
      providerActions += 1;
      return originalList(options);
    };
    const response = await revokeToken(issued.env, issued.refresh, "refresh_token");
    assert.equal(grantReads, 2);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("Retry-After"), "1");
    const body = await response.text();
    assert.deepEqual(JSON.parse(body), { error: "unavailable" });
    assert.equal(body.includes("cd".repeat(32)), false);
    assert.equal(rowWrites(issued.d1) - writes, 2);
    assert.equal(family(issued.d1).pending_id, null);
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.equal(providerActions, 0);
    assert.equal(issued.kv.writes, puts);
    assert.ok(dumpedKv(issued.kv) === stored);
    assertUnavailableLog("oauth.unavailable", "storage_unavailable");
    assertFamilyLogsClean([issued.access, issued.refresh], body);
  });

  it("bounds D1 writes when the callback rejects a grant that changed after the pre-read", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue("notes extra");
    const grantEntry = [...issued.kv.records.entries()].find(([key]) => key.startsWith("grant:"));
    assert.ok(grantEntry);
    const storedGrant = JSON.parse(grantEntry[1].value) as { scope?: string[]; resource?: string };
    const scope = (storedGrant.scope ?? []).join(" ");
    assert.ok(scope.length > 0);
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const originalGet = issued.kv.get.bind(issued.kv);
    const cases: Array<{ name: string; project: (value: Record<string, unknown>) => Record<string, unknown>; status: number; error: string }> = [
      {
        name: "scope",
        project: (value) => ({ ...value, scope: [...(Array.isArray(value.scope) ? value.scope : []), "wider"] }),
        status: 400,
        error: "invalid_scope",
      },
      {
        name: "resource",
        project: (value) => ({ ...value, resource: "https://other.example/mcp" }),
        status: 400,
        error: "invalid_grant",
      },
    ];
    const bodies: string[] = [];
    for (const mismatch of cases) {
      let grantReads = 0;
      issued.kv.get = async (key: string, options?: { type?: string }) => {
        const value = await originalGet(key, options);
        if (!key.startsWith("grant:") || options?.type !== "json" || !value || typeof value !== "object") return value;
        grantReads += 1;
        if (grantReads === 1) return value;
        return mismatch.project(value as Record<string, unknown>);
      };
      for (let attempt = 0; attempt < 4; attempt += 1) {
        grantReads = 0;
        const response = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: issued.refresh,
          client_id: CHATGPT_CLIENT_ID,
          scope,
        }).toString()), issued.env);
        const body = await response.text();
        bodies.push(body);
        if (attempt === 0) {
          assert.equal(response.status, mismatch.status, mismatch.name);
          assert.deepEqual(JSON.parse(body), { error: mismatch.error }, mismatch.name);
        } else {
          assert.equal(response.status, 503, mismatch.name);
          assert.equal(response.headers.get("Retry-After"), "900", mismatch.name);
          assert.deepEqual(JSON.parse(body), { error: "unavailable" }, mismatch.name);
        }
      }
      advance(BUDGET_MS);
      issued.kv.get = originalGet;
    }
    const added = rowWrites(issued.d1) - writes;
    assert.ok(added <= 4, `callback rejections wrote ${added} D1 rows`);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal(family(issued.d1).current_sha256, before.current_sha256);
    const recovered = await rotated(issued.env, issued.refresh);
    assert.equal((await ping(issued.env, recovered.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, recovered.access_token, recovered.refresh_token], bodies.join("\n"));
  });

  it("bounds D1 writes when the callback identity does not match the claimed family", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue("notes extra");
    const grantId = issued.d1.sqlite.prepare("SELECT grant_id AS id FROM oauth_refresh_family").get()?.id;
    if (typeof grantId !== "string") throw new Error("missing grant id");
    const writes = rowWrites(issued.d1);
    let moved = false;
    mock.method(globalThis, "fetch", async () => {
      if (!moved) {
        moved = true;
        issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET grant_id = 'not-the-grant'").run();
      }
      return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
    });
    const bodies: string[] = [];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const response = await refreshGrant(issued.env, issued.refresh);
      const body = await response.text();
      bodies.push(body);
      if (attempt === 0) {
        assert.equal(response.status, 400);
        assert.deepEqual(JSON.parse(body), { error: "invalid_grant" });
      } else {
        assert.equal(response.status, 503);
        assert.equal(response.headers.get("Retry-After"), "900");
        assert.deepEqual(JSON.parse(body), { error: "unavailable" });
      }
    }
    const added = rowWrites(issued.d1) - writes - 1;
    assert.ok(added <= 2, `identity rejection wrote ${added} D1 rows`);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).pending_id, null);
    issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET grant_id = ?").run(grantId);
    advance(BUDGET_MS);
    mock.method(globalThis, "fetch", async () => Response.json(CIMD, { headers: { "Cache-Control": "no-store" } }));
    const recovered = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal((await ping(issued.env, recovered.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, recovered.access_token, recovered.refresh_token], bodies.join("\n"));
  });

  it("bounds D1 writes when the grant disappears between the pre-read and the provider read", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue("notes extra");
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const originalGet = issued.kv.get.bind(issued.kv);
    let grantReads = 0;
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      if (key.startsWith("grant:") && options?.type === "json") {
        grantReads += 1;
        if (grantReads > 1) return null;
      }
      return originalGet(key, options);
    };
    const bodies: string[] = [];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      grantReads = 0;
      const response = await refreshGrant(issued.env, issued.refresh);
      const body = await response.text();
      bodies.push(body);
      if (attempt === 0) {
        assert.equal(response.status, 400);
        assert.deepEqual(JSON.parse(body), { error: "invalid_grant" });
      } else {
        assert.equal(response.status, 503);
        assert.equal(response.headers.get("Retry-After"), "900");
        assert.deepEqual(JSON.parse(body), { error: "unavailable" });
      }
    }
    const added = rowWrites(issued.d1) - writes;
    assert.ok(added <= 2, `a missing grant wrote ${added} D1 rows`);
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).current_sha256, before.current_sha256);
    assert.ok(dumpedKv(issued.kv) === stored);
    issued.kv.get = originalGet;
    advance(BUDGET_MS);
    const recovered = await rotated(issued.env, issued.refresh);
    assert.equal((await ping(issued.env, recovered.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, recovered.access_token, recovered.refresh_token], bodies.join("\n"));
  });

  it("writes nothing when the late claim is busy or deferred", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue("notes extra");
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    let mode: "busy" | "deferred" | "off" = "busy";
    mock.method(globalThis, "fetch", async () => {
      if (mode === "busy") {
        issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET pending_id = 'busy-other' WHERE pending_id IS NULL").run();
      } else if (mode === "deferred") {
        issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET previous_until_ms = ? WHERE previous_until_ms IS NULL").run(Date.now() + 60_000);
      }
      return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
    });
    const bodies: string[] = [];
    const busy = await refreshGrant(issued.env, issued.refresh);
    assert.equal(busy.status, 503);
    assert.equal(busy.headers.get("Retry-After"), "1");
    const busyBody = await busy.text();
    bodies.push(busyBody);
    assert.deepEqual(JSON.parse(busyBody), { error: "unavailable" });
    assertUnavailableLog("oauth.unavailable", "family_busy");
    issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET pending_id = NULL").run();
    mode = "deferred";
    const deferred = await refreshGrant(issued.env, issued.refresh);
    assert.equal(deferred.status, 503);
    assert.equal(deferred.headers.get("Retry-After"), "900");
    const deferredBody = await deferred.text();
    bodies.push(deferredBody);
    assert.deepEqual(JSON.parse(deferredBody), { error: "unavailable" });
    assertUnavailableLog("oauth.unavailable", "refresh_budget");
    const testWrites = 3;
    const added = rowWrites(issued.d1) - writes - testWrites;
    assert.equal(added, 0, `late busy or deferred admission wrote ${added} D1 rows`);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).current_sha256, before.current_sha256);
    assert.ok(dumpedKv(issued.kv) === stored);
    mode = "off";
    advance(BUDGET_MS);
    const recovered = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal((await ping(issued.env, recovered.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, recovered.access_token, recovered.refresh_token], bodies.join("\n"));
  });

  it("revokes on the same request when a late claim finds reuse after an eligible pre-read", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    const writes = rowWrites(issued.d1);
    let displaced = false;
    mock.method(globalThis, "fetch", async () => {
      if (!displaced) {
        displaced = true;
        issued.d1.sqlite.prepare(
          "UPDATE oauth_refresh_family SET current_sha256 = ?, previous_sha256 = NULL, previous_until_ms = NULL, previous_used = 0",
        ).run("ab".repeat(32));
      }
      return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
    });
    const response = await refreshGrant(issued.env, issued.refresh);
    const body = await response.text();
    assert.equal(response.status, 400);
    assert.deepEqual(JSON.parse(body), { error: "invalid_grant" });
    assertFamilyRevoked(issued.d1);
    assert.equal(family(issued.d1).pending_id, null);
    const added = rowWrites(issued.d1) - writes - 1;
    assert.ok(added >= 1, "reuse must revoke the family on this request");
    assertFamilyLogsClean([issued.access, issued.refresh], body);
  });

  it("retries a failed pre-claim KV read without a D1 claim when the provider write also fails", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    assert.equal(family(issued.d1).previous_until_ms, null);
    const before = family(issued.d1);
    const writes = rowWrites(issued.d1);
    const originalGet = issued.kv.get.bind(issued.kv);
    const originalPut = issued.kv.put.bind(issued.kv);
    let failStorage = true;
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      if (failStorage && key.startsWith("grant:")) throw new Error("synthetic kv read failure");
      return originalGet(key, options);
    };
    issued.kv.put = async () => {
      throw new Error("synthetic kv write failure");
    };
    const bodies: string[] = [];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const response = await refreshGrant(issued.env, issued.refresh);
      assert.equal(response.status, 503);
      assert.equal(response.headers.get("Retry-After"), "1");
      const body = await response.text();
      bodies.push(body);
      assert.deepEqual(JSON.parse(body), { error: "unavailable" });
      assert.equal(body.includes("synthetic kv"), false);
    }
    assert.equal(rowWrites(issued.d1), writes, "a KV failure must not claim or release the family");
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    failStorage = false;
    issued.kv.get = originalGet;
    issued.kv.put = originalPut;
    const recovered = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).pending_id, null);
    assert.equal((await ping(issued.env, recovered.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, recovered.access_token, recovered.refresh_token], bodies.join("\n"));
  });

  it("retries when the pre-read disagrees with the provider instead of refusing a healthy family", async () => {
    installFamilyMocks();
    const issued = await issue("notes extra");
    const before = family(issued.d1);
    assert.equal(before.previous_until_ms, null);
    assert.equal(before.pending_id, null);
    const writes = rowWrites(issued.d1);
    const stored = dumpedKv(issued.kv);
    const originalGet = issued.kv.get.bind(issued.kv);
    let disagree = true;
    let grantReads = 0;
    issued.kv.get = async (key: string, options?: { type?: string }) => {
      const value = await originalGet(key, options);
      if (!disagree || !key.startsWith("grant:") || options?.type !== "json" || !value || typeof value !== "object") {
        return value;
      }
      grantReads += 1;
      if (grantReads === 1) {
        return { ...value, refreshTokenId: "ab".repeat(32), previousRefreshTokenId: null };
      }
      return value;
    };
    const disagreed = await refreshGrant(issued.env, issued.refresh);
    assert.equal(disagreed.status, 503);
    assert.equal(disagreed.headers.get("Retry-After"), "1");
    const body = await disagreed.text();
    assert.deepEqual(JSON.parse(body), { error: "unavailable" });
    assert.equal(body.includes("ab".repeat(32)), false);
    assert.equal(rowWrites(issued.d1), writes, "a disagreeing pre-read must not write D1");
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.equal(family(issued.d1).revoked_at, null);
    assert.ok(dumpedKv(issued.kv) === stored, "a disagreeing pre-read must not rotate the grant");
    disagree = false;
    issued.kv.get = originalGet;
    const recovered = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).pending_id, null);
    assert.notEqual(family(issued.d1).current_sha256, before.current_sha256);
    assert.equal((await ping(issued.env, recovered.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, recovered.access_token, recovered.refresh_token], body);
  });

  it("keeps the Worker template on placeholders, CIMD, and quiet invocation logs", () => {
    const template = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../wrangler.example.jsonc"), "utf8");
    assert.equal(template.includes("global_fetch_strictly_public"), true);
    assert.equal(template.includes("enable_request_signal"), true);
    assert.equal(template.includes("OAUTH_KV"), true);
    assert.equal(template.includes("<YOUR_OAUTH_KV_NAMESPACE_ID>"), true);
    assert.equal(template.includes("BRIDGE_ORIGIN"), true);
    assert.equal(template.includes("https://<YOUR_DOMAIN>"), true);
    assert.match(template, /"invocation_logs": false/);
    const migration = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../migrations/0004_connect_code.sql"), "utf8");
    assert.match(migration, /CREATE TABLE connect_code/);
    assert.equal(migration.includes(EMAIL), false);
  });

  it("pins token lifetimes and allows the immediately previous refresh once within sixty seconds", async () => {
    assert.equal(ACCESS_TOKEN_TTL_SECONDS, 3600);
    assert.equal(familyPolicy.REFRESH_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_SECONDS);
    assert.equal(familyPolicy.REFRESH_MIN_INTERVAL_MS, BUDGET_MS);
    assert.equal(familyPolicy.REFRESH_HISTORY_MAX_ROWS, HISTORY_BOUND);
    assert.equal(HISTORY_BOUND, 5764);
    assert.notEqual(ACCESS_TOKEN_TTL_SECONDS, 300);
    assert.equal(REFRESH_TOKEN_TTL_SECONDS, 2_592_000);
    assert.equal(REFRESH_PREVIOUS_GRACE_MS, 60_000);
    const source = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../src/oauth-routes.ts"), "utf8");
    // The wrapper claims a validated token before the provider writes. Neutral
    // callback failures must not accidentally destroy an otherwise live grant.
    assert.match(source, /tokenExchangeCallback:/);
    assert.equal(/OAuthError/.test(source), false);
    assert.match(source, /accessTokenTTL: ACCESS_TOKEN_TTL_SECONDS/);
    assert.match(source, /refreshTokenTTL: REFRESH_TOKEN_TTL_SECONDS/);
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    const remaining = [...issued.kv.records.values()].flatMap((row) => row.expiresAt === undefined ? [] : [row.expiresAt - Date.now() / 1000]);
    assert.ok(remaining.some((ttl) => Math.abs(ttl - ACCESS_TOKEN_TTL_SECONDS) < 30));
    assert.ok(remaining.some((ttl) => Math.abs(ttl - REFRESH_TOKEN_TTL_SECONDS) < 30));
    const method = await routeRequest(new Request(`${ORIGIN}/token`), issued.env);
    assert.equal(method.status, 405);
    assert.match(logs.join("\n"), /"reason":"method_not_allowed"/);

    const firstBody = await rotated(issued.env, issued.refresh);
    assert.equal(firstBody.expires_in, ACCESS_TOKEN_TTL_SECONDS);
    const retryBody = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal((await ping(issued.env, retryBody.access_token)).status, 200);
    advance(BUDGET_MS);
    const continued = await rotated(issued.env, retryBody.refresh_token);
    await assertRefused(issued.env, issued.refresh);
    assertFamilyRevoked(issued.d1);
    assert.match(logs.join("\n"), /"event":"oauth.refused"[\s\S]*"reason":"invalid_grant"/);
    await assertRefused(issued.env, continued.refresh_token);
    assert.equal((await ping(issued.env, continued.access_token)).status, 401);
    assertFamilyLogsClean([issued.access, issued.refresh, firstBody.access_token, firstBody.refresh_token,
      retryBody.access_token, retryBody.refresh_token, continued.access_token, continued.refresh_token]);
  });

  it("allows exactly one parallel refresh successor and keeps that successor usable", async () => {
    installFamilyMocks();
    let now = Date.now();
    mock.method(Date, "now", () => now);
    const concurrent = await issue();
    const initialPosition = family(concurrent.d1).position;
    concurrent.d1.holdWritesUntil(2);
    const pair = await Promise.all([refreshGrant(concurrent.env, concurrent.refresh), refreshGrant(concurrent.env, concurrent.refresh)]);
    assert.deepEqual(pair.map((response) => response.status).sort(), [200, 503]);
    const winner = pair.find((response) => response.status === 200);
    const loser = pair.find((response) => response.status === 503);
    assert.ok(winner && loser);
    const retryAfter = Number(loser.headers.get("Retry-After"));
    const refusal = await loser.text();
    const successor = await winner.json() as IssuedTokens;
    assert.equal(family(concurrent.d1).revoked_at, null);
    assert.equal(family(concurrent.d1).position, initialPosition + 1);
    // Obey the actual advertised delay, just after its boundary. This must
    // leave the benign loser inside the unchanged previous-token grace.
    now += retryAfter * 1000 + 1;
    const recovered = await rotated(concurrent.env, concurrent.refresh);
    assert.equal(retryAfter, REFRESH_BUSY_RETRY_AFTER_SECONDS);
    assert.ok(retryAfter >= 1 && retryAfter <= 2);
    assertUnavailableLog("oauth.unavailable", "family_busy");
    assert.equal(family(concurrent.d1).revoked_at, null);
    now += BUDGET_MS;
    const continued = await rotated(concurrent.env, recovered.refresh_token);
    assert.equal((await ping(concurrent.env, continued.access_token)).status, 200);
    assertFamilyLogsClean([concurrent.access, concurrent.refresh, successor.access_token, successor.refresh_token,
      recovered.access_token, recovered.refresh_token, continued.access_token, continued.refresh_token], refusal);
  });

  for (const pending of [null, "synthetic-pending"] as const) {
    it(`refuses untracked provider-valid refresh when the enrolled family is ${pending === null ? "idle" : "busy"}`, async () => {
      installFamilyMocks();
      const issued = await issue();
      const opened = openAuthorizationServer(issued.env);
      assert.ok(opened);
      // Model an older Worker during rollback: the unchanged provider rotates
      // synthetic KV directly, so D1 retains its earlier current/hash history.
      const response = await opened.server.fetch(postForm(`${ORIGIN}/token`, new URLSearchParams({
        grant_type: "refresh_token", refresh_token: issued.refresh, client_id: CHATGPT_CLIENT_ID,
      }).toString()), { OAUTH_KV: issued.env.OAUTH_KV }, {
        waitUntil(promise: Promise<unknown>) { void promise.catch(() => undefined); },
        passThroughOnException() {}, abort() {}, props: {},
      } as ExecutionContext);
      assert.equal(response.status, 200);
      const untracked = await response.json() as IssuedTokens;
      assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_token WHERE token_sha256 = ?")
        .get(tokenHash(untracked.refresh_token))?.n, 0);
      issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET pending_id = ?").run(pending);
      const before = family(issued.d1);
      const stored = dumpedKv(issued.kv);
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const refused = await refreshGrant(issued.env, untracked.refresh_token);
        assert.equal(refused.status, pending === null ? 400 : 503);
        if (pending !== null) assert.equal(refused.headers.get("Retry-After"), String(REFRESH_BUSY_RETRY_AFTER_SECONDS));
        else assert.equal(refused.headers.get("Retry-After"), null);
        const body = await refused.text();
        assert.ok(isDeepStrictEqual(JSON.parse(body), { error: pending === null ? "invalid_grant" : "unavailable" }));
        assert.ok(isDeepStrictEqual(family(issued.d1), before));
        assert.ok(dumpedKv(issued.kv) === stored, "refusal must precede provider writes");
        assertFamilyLogsClean([issued.access, issued.refresh, untracked.access_token, untracked.refresh_token], body);
      }
    });
  }

  it("defers an early current-token rotation without any D1 or KV write and admits it at the budget boundary", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    const before = JSON.stringify([family(issued.d1),
      issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_token ORDER BY position").all(),
      issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all()]);
    const stored = dumpedKv(issued.kv);
    const writes = rowWrites(issued.d1);
    const bodies: string[] = [];
    for (const [elapsed, retryAfter] of [[1000, BUDGET_MS / 1000 - 1], [BUDGET_MS - 1001, 1]] as const) {
      advance(elapsed);
      const deferred = await refreshGrant(issued.env, first.refresh_token);
      assert.equal(deferred.status, 503);
      assert.equal(deferred.headers.get("Retry-After"), String(retryAfter));
      const body = await deferred.text();
      bodies.push(body);
      assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "unavailable" }));
      assert.equal(rowWrites(issued.d1), writes, "a deferred rotation must not write D1");
      assert.ok(dumpedKv(issued.kv) === stored, "a deferred rotation must precede provider writes");
      assert.ok(JSON.stringify([family(issued.d1),
        issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_token ORDER BY position").all(),
        issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all()]) === before);
      assert.equal((await ping(issued.env, first.access_token)).status, 200);
    }
    assertUnavailableLog("oauth.unavailable", "refresh_budget");
    advance(1);
    const admitted = await rotated(issued.env, first.refresh_token);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.ok(family(issued.d1).current_sha256 === tokenHash(admitted.refresh_token));
    assert.equal((await ping(issued.env, admitted.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token,
      admitted.access_token, admitted.refresh_token], bodies.join("\n"));
  });

  it("keeps the one-use grace retry outside the budget and budgets its successor from the original rotation", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    advance(1000);
    const early = await refreshGrant(issued.env, first.refresh_token);
    assert.equal(early.status, 503);
    const earlyBody = await early.text();
    advance(1000);
    const recovered = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).previous_used, 1);
    advance(1000);
    const successor = await refreshGrant(issued.env, recovered.refresh_token);
    assert.equal(successor.status, 503);
    assert.equal(successor.headers.get("Retry-After"), String(BUDGET_MS / 1000 - 3));
    const successorBody = await successor.text();
    assert.equal(family(issued.d1).revoked_at, null);
    advance(BUDGET_MS - 3000);
    const continued = await rotated(issued.env, recovered.refresh_token);
    assert.equal((await ping(issued.env, continued.access_token)).status, 200);
    await assertRefused(issued.env, issued.refresh);
    assertFamilyRevoked(issued.d1);
    await assertRefused(issued.env, continued.refresh_token);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token,
      recovered.access_token, recovered.refresh_token, continued.access_token, continued.refresh_token],
    `${earlyBody}\n${successorBody}`);
  });

  it("caps one chain at two rotations per budget interval across a simulated day of refresh attempts", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    const writes = rowWrites(issued.d1);
    let current = issued.refresh;
    let rotations = 0;
    let deferred = 0;
    const day = 86_400_000;
    for (let elapsed = 0; elapsed < day; elapsed += 60_000) {
      const response = await refreshGrant(issued.env, current);
      if (response.status === 503) {
        deferred += 1;
        await response.body?.cancel();
      } else {
        // Each admitted rotation is followed by its one-use grace retry.
        assert.equal(response.status, 200);
        const previous = current;
        current = (await response.json() as IssuedTokens).refresh_token;
        current = (await rotated(issued.env, previous)).refresh_token;
        rotations += 2;
      }
      advance(60_000);
    }
    const ceiling = 2 * (Math.floor(day / BUDGET_MS) + 1);
    assert.ok(rotations <= ceiling, `${rotations} rotations exceed ${ceiling}`);
    assert.ok(rotations >= ceiling - 2, "the budget must still admit a rotation every interval");
    assert.ok(deferred > 0);
    // Three table rows per rotation: the claim, the history row and the family update.
    const rowsWritten = rowWrites(issued.d1) - writes;
    assert.ok(rowsWritten <= 3 * ceiling, `${rowsWritten} D1 rows written in one day`);
    assert.equal(family(issued.d1).revoked_at, null);
    assert.ok(Number(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_token").get()?.n) <= HISTORY_BOUND);
  });

  for (const replay of ["current token at the bound", "oldest recorded ancestor"] as const) {
    it(`keeps history within the hard bound and refuses the ${replay} with family revocation`, async () => {
      installFamilyMocks();
      const advance = steppedClock();
      const issued = await issue();
      const first = await rotated(issued.env, issued.refresh);
      // Model a family that has used its lifetime budget: every position from 0
      // up to the current token is recorded, with the issued token still at 1.
      const id = (issued.d1.sqlite.prepare("SELECT id FROM oauth_refresh_family").get() as { id: string }).id;
      issued.d1.sqlite.exec("BEGIN");
      issued.d1.sqlite.prepare("UPDATE oauth_refresh_token SET position = ? WHERE token_sha256 = ?")
        .run(HISTORY_BOUND - 2, tokenHash(first.refresh_token));
      issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET position = ?").run(HISTORY_BOUND - 2);
      const synthetic = issued.d1.sqlite.prepare("INSERT INTO oauth_refresh_token (token_sha256, family_id, position) VALUES (?, ?, ?)");
      for (let position = 0; position < HISTORY_BOUND - 2; position += 1) {
        if (position !== 1) synthetic.run(tokenHash(`synthetic-history-${position}`), id, position);
      }
      issued.d1.sqlite.exec("COMMIT");
      const count = () => Number(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_token").get()?.n);
      assert.equal(count(), HISTORY_BOUND - 1);
      advance(BUDGET_MS);
      const last = await rotated(issued.env, first.refresh_token);
      assert.equal(count(), HISTORY_BOUND);
      assert.equal(family(issued.d1).position, HISTORY_BOUND - 1);
      advance(BUDGET_MS);
      const stored = dumpedKv(issued.kv);
      await assertRefused(issued.env, replay === "oldest recorded ancestor" ? issued.refresh : last.refresh_token);
      assertFamilyRevoked(issued.d1);
      assert.ok(dumpedKv(issued.kv) === stored, "a refused rotation at the bound must precede provider writes");
      await assertRefused(issued.env, last.refresh_token);
      await assertRefused(issued.env, issued.refresh);
      assert.equal((await ping(issued.env, last.access_token)).status, 401);
      assert.equal(count(), HISTORY_BOUND);
      assert.equal(Number(issued.d1.sqlite.prepare("SELECT max(position) AS n FROM oauth_refresh_token").get()?.n), HISTORY_BOUND - 1);
      assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 1);
      assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token,
        last.access_token, last.refresh_token]);
    });
  }

  it("uses the same admission clock before and after the primary family read", async () => {
    installFamilyMocks();
    const issued = await issue();
    const successor = await rotated(issued.env, issued.refresh);
    const admittedAt = Date.now();
    issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET pending_id = 'synthetic-pending', previous_until_ms = ?")
      .run(admittedAt + 1);
    let reads = 0;
    mock.method(Date, "now", () => reads++ === 0 ? admittedAt : admittedAt + 2);
    const exchange = new RefreshFamilyExchange(issued.env.DB, tokenHash(issued.refresh), CHATGPT_CLIENT_ID);
    await assert.rejects(exchange.prepare(), (error: unknown) => error instanceof RefreshFamilyBusy);
    assert.equal(family(issued.d1).revoked_at, null);
    assertFamilyLogsClean([issued.access, issued.refresh, successor.access_token, successor.refresh_token]);
  });

  it("enrolls a legacy grant's first presented refresh at position zero and refuses its later ancestor", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    issued.d1.sqlite.prepare("DELETE FROM oauth_refresh_family").run();
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_token").get()?.n, 0);
    const first = await rotated(issued.env, issued.refresh);
    const history = issued.d1.sqlite.prepare("SELECT token_sha256, position FROM oauth_refresh_token ORDER BY position").all();
    assert.ok(isDeepStrictEqual(history.map((row) => ({ ...row })), [
      { token_sha256: tokenHash(issued.refresh), position: 0 },
      { token_sha256: tokenHash(first.refresh_token), position: 1 },
    ]));
    advance(BUDGET_MS);
    const current = await rotated(issued.env, first.refresh_token);
    await assertRefused(issued.env, issued.refresh);
    assertFamilyRevoked(issued.d1);
    await assertRefused(issued.env, current.refresh_token);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token,
      current.access_token, current.refresh_token]);
  });

  it("revokes the displaced former current token after a previous-token grace retry", async () => {
    installFamilyMocks();
    const issued = await issue();
    const displaced = await rotated(issued.env, issued.refresh);
    const recovered = await rotated(issued.env, issued.refresh);
    await assertRefused(issued.env, displaced.refresh_token);
    assertFamilyRevoked(issued.d1);
    await assertRefused(issued.env, recovered.refresh_token);
    assert.equal((await ping(issued.env, recovered.access_token)).status, 401);
    assertFamilyLogsClean([issued.access, issued.refresh, displaced.access_token, displaced.refresh_token,
      recovered.access_token, recovered.refresh_token]);
  });

  it("keeps a stale claim busy until owner revocation and reconnect creates a new usable family", async () => {
    installFamilyMocks();
    const issued = await issue();
    issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET pending_id = 'synthetic-abandoned'").run();
    const busy = await refreshGrant(issued.env, issued.refresh);
    assert.equal(busy.status, 503);
    assert.equal(busy.headers.get("Retry-After"), String(REFRESH_BUSY_RETRY_AFTER_SECONDS));
    const busyBody = await busy.text();
    assertUnavailableLog("oauth.unavailable", "family_busy");
    issued.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ? WHERE participant = 'dot' AND revoked_at IS NULL")
      .run(new Date().toISOString());
    await assertRefused(issued.env, issued.refresh);
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    const connectCode = randomBytes(32).toString("base64url");
    issued.d1.sqlite.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, ?, NULL)")
      .run(tokenHash(connectCode), OWNER, new Date(Date.now() + 600_000).toISOString());
    const { verifier, challenge } = pkce();
    const consent = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge, { connect_code: connectCode })), issued.env);
    assert.equal(consent.status, 303);
    const code = new URL(consent.headers.get("Location") ?? "").searchParams.get("code");
    assert.ok(code);
    const result = await exchangeCode(issued.env, code, verifier);
    assert.equal(result.status, 200);
    const connected = await result.json() as IssuedTokens;
    assert.equal((await ping(issued.env, connected.access_token)).status, 200);
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 2);
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family WHERE revoked_at IS NULL").get()?.n, 1);
    assertFamilyLogsClean([issued.access, issued.refresh, connectCode, code, verifier,
      connected.access_token, connected.refresh_token], busyBody);
  });

  it("rejects a forged client assertion with an old recorded token without revoking its family", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    advance(BUDGET_MS);
    const current = await rotated(issued.env, first.refresh_token);
    const assertion = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ iss: CHATGPT_CLIENT_ID })).toString("base64url")}.sig`;
    const before = family(issued.d1);
    const stored = dumpedKv(issued.kv);
    const refused = await routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "refresh_token", refresh_token: issued.refresh, client_id: CHATGPT_CLIENT_ID,
      client_assertion: assertion, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString()), issued.env);
    const body = await refused.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "invalid_client" }));
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.ok(dumpedKv(issued.kv) === stored);
    assert.equal((await ping(issued.env, current.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token,
      current.access_token, current.refresh_token, assertion], body);
  });

  it("forbids clearing a family's revocation timestamp without changing its stored state", async () => {
    installFamilyMocks();
    const issued = await issue();
    issued.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ? WHERE participant = 'dot' AND revoked_at IS NULL")
      .run(new Date().toISOString());
    const before = family(issued.d1);
    assert.throws(() => issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET revoked_at = NULL").run(), /revocation_immutable/);
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assertFamilyRevoked(issued.d1);
    await assertRefused(issued.env, issued.refresh);
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    assertFamilyLogsClean([issued.access, issued.refresh]);
  });

  it("creates one hashed refresh family and records every rotation without storing token values", async () => {
    installFamilyMocks();
    const issued = await issue();
    const initial = family(issued.d1);
    assert.ok(initial.current_sha256 === tokenHash(issued.refresh));
    assert.equal(initial.previous_sha256, null);
    assert.ok(initial.position >= 0);
    assert.equal(initial.pending_id, null);
    assert.equal(initial.revoked_at, null);
    const first = await rotated(issued.env, issued.refresh);
    const current = family(issued.d1);
    assert.ok(current.current_sha256 === tokenHash(first.refresh_token));
    assert.ok(current.previous_sha256 === tokenHash(issued.refresh));
    assert.equal(current.position, initial.position + 1);
    assert.equal(current.previous_used, 0);
    assert.equal(current.pending_id, null);
    assert.ok(typeof current.previous_until_ms === "number");
    assert.ok(Math.abs(current.previous_until_ms - Date.now() - REFRESH_PREVIOUS_GRACE_MS) < 5000);
    const history = issued.d1.sqlite.prepare(
      "SELECT token_sha256, position FROM oauth_refresh_token ORDER BY position",
    ).all().map((row) => ({ ...row }));
    assert.ok(isDeepStrictEqual(history, [
      { token_sha256: tokenHash(issued.refresh), position: initial.position },
      { token_sha256: tokenHash(first.refresh_token), position: initial.position + 1 },
    ]));
    const stored = JSON.stringify([
      issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_family").all(),
      issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_token").all(),
    ]);
    const tokens = [issued.access, issued.refresh, first.access_token, first.refresh_token];
    assertClean(stored, tokens);
    assertFamilyLogsClean(tokens);
  });

  it("revokes the whole family on a second immediately previous refresh use within the grace window", async () => {
    installFamilyMocks();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    const retry = await rotated(issued.env, issued.refresh);
    assert.equal(family(issued.d1).revoked_at, null);
    await assertRefused(issued.env, issued.refresh);
    assertFamilyRevoked(issued.d1);
    await assertRefused(issued.env, retry.refresh_token);
    assert.equal((await ping(issued.env, first.access_token)).status, 401);
    assert.equal((await ping(issued.env, retry.access_token)).status, 401);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token,
      retry.access_token, retry.refresh_token]);
  });

  it("revokes the whole family when the previous refresh is reused after sixty seconds", async () => {
    installFamilyMocks();
    let now = Date.now();
    mock.method(Date, "now", () => now);
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    now += REFRESH_PREVIOUS_GRACE_MS + 1;
    await assertRefused(issued.env, issued.refresh);
    assertFamilyRevoked(issued.d1);
    await assertRefused(issued.env, first.refresh_token);
    assert.equal((await ping(issued.env, first.access_token)).status, 401);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token]);
  });

  it("revokes the whole family when any grandparent refresh is reused", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    advance(BUDGET_MS);
    const second = await rotated(issued.env, first.refresh_token);
    await assertRefused(issued.env, issued.refresh);
    assertFamilyRevoked(issued.d1);
    await assertRefused(issued.env, second.refresh_token);
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    assert.equal((await ping(issued.env, second.access_token)).status, 401);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token,
      second.access_token, second.refresh_token]);
  });

  it("revokes an older ancestor even while a current rotation is pending", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    advance(BUDGET_MS);
    const current = await rotated(issued.env, first.refresh_token);
    // Model another request's admitted claim without issuing a second live
    // provider write. An invalid ancestor is reuse, not a retryable lock loser.
    issued.d1.sqlite.prepare("UPDATE oauth_refresh_family SET pending_id = 'synthetic-pending'").run();
    await assertRefused(issued.env, issued.refresh);
    assertFamilyRevoked(issued.d1);
    await assertRefused(issued.env, current.refresh_token);
    assert.equal((await ping(issued.env, current.access_token)).status, 401);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token,
      current.access_token, current.refresh_token]);
  });

  it("can execute migration 0008 twice without changing existing family data or duplicating its schema", async () => {
    installFamilyMocks();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    const snapshot = () => [
      issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_family ORDER BY id").all(),
      issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_token ORDER BY position").all(),
      issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(),
    ];
    const before = snapshot();
    const sql = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../migrations/0008_refresh_token_family.sql"), "utf8");
    // SqliteD1 already loaded the schema. Re-execute only this additive file,
    // twice, using plain node:sqlite; no D1 runner or operator binding is used.
    issued.d1.sqlite.exec(sql);
    issued.d1.sqlite.exec(sql);
    assert.ok(isDeepStrictEqual(snapshot(), before));
    assert.equal(issued.d1.sqlite.prepare(
      "SELECT count(*) AS n FROM sqlite_schema WHERE type = 'table' AND name IN ('oauth_refresh_family', 'oauth_refresh_token')",
    ).get()?.n, 2);
    assert.equal(issued.d1.sqlite.prepare(
      "SELECT count(*) AS n FROM sqlite_schema WHERE type = 'trigger' AND name IN ('oauth_family_revoke_credential', 'oauth_credential_revoke_family', 'oauth_family_no_unrevoke')",
    ).get()?.n, 3);
    const foreignKey = issued.d1.sqlite.prepare("PRAGMA foreign_key_list(oauth_refresh_family)").all()
      .find((row) => row.from === "credential_id");
    assert.equal(foreignKey?.table, "participant_credential");
    assert.equal(foreignKey?.on_delete, "NO ACTION");
    assert.equal(issued.d1.sqlite.prepare(
      "SELECT tbl_name FROM sqlite_schema WHERE type = 'trigger' AND name = 'oauth_credential_revoke_family'",
    ).get()?.tbl_name, "participant_credential");
    assert.equal((await ping(issued.env, first.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token]);
  });

  it("records owner revocation in place and blocks existing access and refresh tokens on the next request", async () => {
    installFamilyMocks();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    assert.equal((await ping(issued.env, issued.access)).status, 200);
    assert.equal((await ping(issued.env, first.access_token)).status, 200);
    const revokedAt = new Date().toISOString();
    issued.d1.sqlite.prepare(
      "UPDATE participant_credential SET revoked_at = ? WHERE participant = 'dot' AND revoked_at IS NULL",
    ).run(revokedAt);
    assert.equal(family(issued.d1).revoked_at, revokedAt);
    assertFamilyRevoked(issued.d1);
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    assert.equal((await ping(issued.env, first.access_token)).status, 401);
    await assertRefused(issued.env, first.refresh_token);
    await assertRefused(issued.env, issued.refresh);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token]);
  });

  it("temporarily refuses a disabled participant without changing its grant and resumes the same refresh after enable", async () => {
    installFamilyMocks();
    const issued = await issue();
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'dot'").run();
    const stored = dumpedKv(issued.kv);
    const credentials = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
    const before = family(issued.d1);
    const tokens = issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_token ORDER BY position").all();
    for (const response of [await refreshGrant(issued.env, issued.refresh), await ping(issued.env, issued.access)]) {
      assert.equal(response.status, 503);
      assert.equal(response.headers.get("Retry-After"), "60");
      const body = await response.text();
      assert.deepEqual(JSON.parse(body), { error: "unavailable" });
      assertFamilyLogsClean([issued.access, issued.refresh], body);
    }
    assertUnavailableLog("oauth.unavailable", "participant_disabled");
    assertUnavailableLog("mcp.unavailable", "participant_disabled");
    assert.ok(dumpedKv(issued.kv) === stored);
    assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), credentials));
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_token ORDER BY position").all(), tokens));
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = 'dot'").run();
    assert.equal((await ping(issued.env, issued.access)).status, 200);
    const resumed = await rotated(issued.env, issued.refresh);
    assert.equal((await ping(issued.env, resumed.access_token)).status, 200);
    assert.equal(family(issued.d1).revoked_at, null);
    assertFamilyLogsClean([issued.access, issued.refresh, resumed.access_token, resumed.refresh_token]);
  });

  it("temporarily refuses protocol revocation of a disabled participant's access token and preserves its grant", async () => {
    installFamilyMocks();
    const issued = await issue();
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'dot'").run();
    const stored = dumpedKv(issued.kv);
    const before = family(issued.d1);
    const credentials = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
    const response = await revokeToken(issued.env, issued.access, "access_token");
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("Retry-After"), "60");
    const refusal = await response.text();
    assert.ok(isDeepStrictEqual(JSON.parse(refusal), { error: "unavailable" }));
    assert.ok(dumpedKv(issued.kv) === stored, "temporary pause must not change provider storage");
    assert.ok(isDeepStrictEqual(family(issued.d1), before));
    assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), credentials));
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = 'dot'").run();
    assert.equal((await ping(issued.env, issued.access)).status, 200);
    const resumed = await rotated(issued.env, issued.refresh);
    assert.equal((await ping(issued.env, resumed.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, resumed.access_token, resumed.refresh_token], refusal);
  });

  it("records protocol refresh-token revocation in D1 and refuses existing access and refresh immediately", async () => {
    installFamilyMocks();
    const issued = await issue();
    const first = await rotated(issued.env, issued.refresh);
    const response = await revokeToken(issued.env, first.refresh_token, "refresh_token");
    assert.equal(response.status, 200);
    const body = await response.text();
    assertFamilyRevoked(issued.d1);
    const credential = issued.d1.sqlite.prepare(
      "SELECT revoked_at FROM participant_credential WHERE id = (SELECT credential_id FROM oauth_refresh_family)",
    ).get();
    assert.ok(credential?.revoked_at === family(issued.d1).revoked_at);
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    assert.equal((await ping(issued.env, first.access_token)).status, 401);
    await assertRefused(issued.env, issued.refresh);
    await assertRefused(issued.env, first.refresh_token);
    assertFamilyLogsClean([issued.access, issued.refresh, first.access_token, first.refresh_token], body);
  });

  for (const [name, hint, empty] of [
    ["refresh hint", "refresh_token", false],
    ["access hint", "access_token", false],
    ["no hint", undefined, false],
    ["no access records", "refresh_token", true],
  ] as const) {
    it(`preserves a paused legacy refresh grant during protocol revocation with ${name}`, async () => {
      installFamilyMocks();
      const issued = await issue();
      issued.d1.sqlite.prepare("DELETE FROM oauth_refresh_family").run();
      if (empty) {
        for (const key of [...issued.kv.records.keys()]) if (key.startsWith("token:")) await issued.kv.delete(key);
      }
      issued.d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'dot'").run();
      const stored = dumpedKv(issued.kv);
      const credentials = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
      let lists = 0, deletes = 0;
      const list = issued.kv.list.bind(issued.kv), remove = issued.kv.delete.bind(issued.kv);
      issued.kv.list = async (...args: Parameters<MemoryKv["list"]>) => { lists += 1; return list(...args); };
      issued.kv.delete = async (...args: Parameters<MemoryKv["delete"]>) => { deletes += 1; return remove(...args); };
      const response = await revokeToken(issued.env, issued.refresh, hint);
      assert.equal(response.status, 503);
      assert.equal(response.headers.get("Retry-After"), "60");
      const body = await response.text();
      assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "unavailable" }));
      assert.equal(lists, 0, "pause must be checked before the provider lists access records");
      assert.equal(deletes, 0, "pause must be checked before any provider deletion");
      assert.ok(dumpedKv(issued.kv) === stored);
      assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), credentials));
      assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 0);
      assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_token").get()?.n, 0);
      assertUnavailableLog("oauth.unavailable", "participant_disabled");
      issued.d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = 'dot'").run();
      const resumed = await rotated(issued.env, issued.refresh);
      assert.equal((await ping(issued.env, resumed.access_token)).status, 200);
      assertFamilyLogsClean([issued.access, issued.refresh, resumed.access_token, resumed.refresh_token], body);
    });
  }

  it("preserves enabled legacy whole-grant revocation for every token-type hint without inferring a credential", async () => {
    installFamilyMocks();
    for (const hint of ["refresh_token", "access_token", undefined] as const) {
      const issued = await issue();
      issued.d1.sqlite.prepare("DELETE FROM oauth_refresh_family").run();
      const credentials = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
      const response = await revokeToken(issued.env, issued.refresh, hint);
      assert.equal(response.status, 200);
      const body = await response.text();
      assert.ok(![...issued.kv.records.keys()].some((key) => key.startsWith("grant:") || key.startsWith("token:")));
      assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), credentials));
      assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 0);
      assert.equal((await ping(issued.env, issued.access)).status, 401);
      await assertRefused(issued.env, issued.refresh);
      assertFamilyLogsClean([issued.access, issued.refresh], body);
    }
  });

  it("does not pause or revoke an unauthenticated legacy grant selected by a wrong client or forged token", async () => {
    installFamilyMocks();
    mock.method(globalThis, "fetch", async (input: unknown) => {
      const clientId = input instanceof Request ? input.url : String(input);
      return Response.json({ ...CIMD, client_id: clientId,
        redirect_uris: [clientId === CLAUDE_CLIENT_ID ? CLAUDE_REDIRECT : CHATGPT_REDIRECT] }, { headers: { "Cache-Control": "no-store" } });
    });
    const issued = await issue();
    issued.d1.sqlite.prepare("DELETE FROM oauth_refresh_family").run();
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'dot'").run();
    const forged = `${issued.refresh.slice(0, issued.refresh.lastIndexOf(":") + 1)}${randomBytes(32).toString("base64url")}`;
    const stored = dumpedKv(issued.kv);
    const credentials = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
    for (const [token, clientId] of [[issued.refresh, CLAUDE_CLIENT_ID], [forged, CHATGPT_CLIENT_ID]]) {
      const response = await revokeToken(issued.env, token ?? "", "refresh_token", clientId);
      assert.equal(response.status, 200);
      const body = await response.text();
      assert.ok(dumpedKv(issued.kv) === stored);
      assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), credentials));
      assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 0);
      assertFamilyLogsClean([issued.access, issued.refresh, forged], body);
    }
  });

  it("keeps individual access-token revocation token-specific for enrolled and legacy grants with every hint", async () => {
    installFamilyMocks();
    for (const enrolled of [true, false]) for (const hint of ["refresh_token", "access_token", undefined] as const) {
      const issued = await issue();
      if (!enrolled) issued.d1.sqlite.prepare("DELETE FROM oauth_refresh_family").run();
      const families = issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_family").all();
      const credentials = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
      const response = await revokeToken(issued.env, issued.access, hint);
      assert.equal(response.status, 200);
      const body = await response.text();
      assert.ok([...issued.kv.records.keys()].some((key) => key.startsWith("grant:")));
      assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM oauth_refresh_family").all(), families));
      assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), credentials));
      assert.equal((await ping(issued.env, issued.access)).status, 401);
      const resumed = await rotated(issued.env, issued.refresh);
      assert.equal((await ping(issued.env, resumed.access_token)).status, 200);
      assertFamilyLogsClean([issued.access, issued.refresh, resumed.access_token, resumed.refresh_token], body);
    }
  });

  it("fails closed before legacy refresh cleanup when the provider-authorized D1 pause lookup fails", async () => {
    installFamilyMocks();
    const issued = await issue();
    issued.d1.sqlite.prepare("DELETE FROM oauth_refresh_family").run();
    const stored = dumpedKv(issued.kv);
    const credentials = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
    const get = issued.kv.get.bind(issued.kv);
    let armed = false, lists = 0, deletes = 0;
    issued.kv.get = async (...args: Parameters<MemoryKv["get"]>) => {
      const value = await get(...args);
      if (args[0].startsWith("grant:") && !armed) {
        issued.d1.failNextWrite(new Error("synthetic legacy revocation lookup unavailable"));
        armed = true;
      }
      return value;
    };
    const list = issued.kv.list.bind(issued.kv), remove = issued.kv.delete.bind(issued.kv);
    issued.kv.list = async (...args: Parameters<MemoryKv["list"]>) => { lists += 1; return list(...args); };
    issued.kv.delete = async (...args: Parameters<MemoryKv["delete"]>) => { deletes += 1; return remove(...args); };
    const response = await revokeToken(issued.env, issued.refresh, "refresh_token");
    assert.ok(armed, "failure must follow provider ownership validation");
    assert.equal(response.status, 500);
    const body = await response.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "internal_error" }));
    assert.equal(lists, 0);
    assert.equal(deletes, 0);
    assert.ok(dumpedKv(issued.kv) === stored);
    assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), credentials));
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 0);
    assert.ok(!`${logs.join("\n")}\n${body}`.includes("synthetic legacy revocation lookup unavailable"));
    assertFamilyLogsClean([issued.access, issued.refresh], body);
  });

  it("revokes an exchanged authorization code's family and provider records when the exact code is replayed", async () => {
    installFamilyMocks();
    const issued = await issue();
    const current = await rotated(issued.env, issued.refresh);
    const response = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(response.status, 400);
    const body = await response.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "invalid_grant" }));
    const revokedAt = family(issued.d1).revoked_at;
    const credential = issued.d1.sqlite.prepare(
      "SELECT revoked_at FROM participant_credential WHERE id = (SELECT credential_id FROM oauth_refresh_family)",
    ).get();
    const state = {
      familyRevoked: revokedAt !== null,
      credentialRevoked: credential?.revoked_at !== null && credential?.revoked_at === revokedAt,
      originalAccessRefused: (await ping(issued.env, issued.access)).status === 401,
      currentAccessRefused: (await ping(issued.env, current.access_token)).status === 401,
      grantRecordsRemoved: ![...issued.kv.records.keys()].some((key) => key.startsWith("grant:")),
      accessRecordsRemoved: ![...issued.kv.records.keys()].some((key) => key.startsWith("token:")),
      originalRefreshRefused: (await refreshGrant(issued.env, issued.refresh)).status === 400,
      currentRefreshRefused: (await refreshGrant(issued.env, current.refresh_token)).status === 400,
    };
    assert.ok(Object.values(state).every(Boolean), "exact exchanged-code replay must revoke D1 and remove provider records");
    assertFamilyLogsClean([issued.code, issued.verifier, issued.access, issued.refresh,
      current.access_token, current.refresh_token], body);
  });

  it("revokes an exchanged authorization code's family when its grant has no access-token records", async () => {
    installFamilyMocks();
    const issued = await issue();
    for (const key of issued.kv.records.keys()) {
      if (key.startsWith("token:")) issued.kv.records.delete(key);
    }
    const response = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(response.status, 400);
    const body = await response.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "invalid_grant" }));
    const state = {
      familyRevoked: family(issued.d1).revoked_at !== null,
      credentialRevoked: issued.d1.sqlite.prepare(
        "SELECT count(*) AS n FROM participant_credential WHERE participant = 'dot' AND revoked_at IS NULL",
      ).get()?.n === 0,
      grantRecordsRemoved: ![...issued.kv.records.keys()].some((key) => key.startsWith("grant:")),
      refreshRefused: (await refreshGrant(issued.env, issued.refresh)).status === 400,
    };
    assert.ok(Object.values(state).every(Boolean), "grant deletion without token deletion must still revoke its D1 family");
    assertFamilyLogsClean([issued.code, issued.verifier, issued.access, issued.refresh], body);
  });

  it("pauses replay of an exchanged authorization code while disabled and revokes it after enable", async () => {
    installFamilyMocks();
    const issued = await issue();
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'dot'").run();
    const beforeKv = dumpedKv(issued.kv);
    const beforeFamily = family(issued.d1);
    const beforeCredential = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
    const paused = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(paused.status, 503);
    assert.equal(paused.headers.get("Retry-After"), "60");
    const pausedBody = await paused.text();
    assert.ok(isDeepStrictEqual(JSON.parse(pausedBody), { error: "unavailable" }));
    assert.ok(dumpedKv(issued.kv) === beforeKv, "a swallowed provider cleanup error must not destroy a paused grant");
    assert.ok(isDeepStrictEqual(family(issued.d1), beforeFamily));
    assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), beforeCredential));
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = 'dot'").run();
    assert.equal((await ping(issued.env, issued.access)).status, 200);
    const replay = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(replay.status, 400);
    const replayBody = await replay.text();
    assert.ok(isDeepStrictEqual(JSON.parse(replayBody), { error: "invalid_grant" }));
    assertFamilyRevoked(issued.d1);
    assert.ok(![...issued.kv.records.keys()].some((key) => key.startsWith("grant:") || key.startsWith("token:")));
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    await assertRefused(issued.env, issued.refresh);
    assertFamilyLogsClean([issued.code, issued.verifier, issued.access, issued.refresh], `${pausedBody}\n${replayBody}`);
  });

  it("pauses legacy unmapped code cleanup while disabled without guessing a D1 credential", async () => {
    installFamilyMocks();
    const issued = await issue();
    // Model a provider grant issued before family tracking was installed. Its
    // provider-validated cleanup target has no current D1 family mapping.
    issued.d1.sqlite.prepare("DELETE FROM oauth_refresh_family").run();
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_token").get()?.n, 0);
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'dot'").run();
    const beforeKv = dumpedKv(issued.kv);
    const beforeCredential = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
    const paused = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(paused.status, 503);
    assert.equal(paused.headers.get("Retry-After"), "60");
    const pausedBody = await paused.text();
    assert.ok(isDeepStrictEqual(JSON.parse(pausedBody), { error: "unavailable" }));
    assert.ok(dumpedKv(issued.kv) === beforeKv, "an unmapped paused grant must retain its provider records");
    assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), beforeCredential));
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 0);
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = 'dot'").run();
    assert.equal((await ping(issued.env, issued.access)).status, 200);
    const replay = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(replay.status, 400);
    const replayBody = await replay.text();
    assert.ok(isDeepStrictEqual(JSON.parse(replayBody), { error: "invalid_grant" }));
    assert.ok(![...issued.kv.records.keys()].some((key) => key.startsWith("grant:") || key.startsWith("token:")));
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    await assertRefused(issued.env, issued.refresh);
    // Neither the current credential nor the unrelated superseded credential
    // can be inferred from an unmapped provider grant. Both remain unchanged.
    assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), beforeCredential));
    assert.equal(issued.d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 0);
    assertFamilyLogsClean([issued.code, issued.verifier, issued.access, issued.refresh], `${pausedBody}\n${replayBody}`);
  });

  it("reports D1 cleanup failure for an exchanged authorization code before changing provider records", async () => {
    installFamilyMocks();
    const issued = await issue();
    const beforeKv = dumpedKv(issued.kv);
    const beforeFamily = family(issued.d1);
    const beforeCredential = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
    issued.d1.failNextWrite(new Error("synthetic replay cleanup D1 unavailable"));
    const failed = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(failed.status, 500);
    const failedBody = await failed.text();
    assert.ok(isDeepStrictEqual(JSON.parse(failedBody), { error: "internal_error" }));
    assert.ok(dumpedKv(issued.kv) === beforeKv, "D1 revocation failure must precede and block KV cleanup");
    assert.ok(isDeepStrictEqual(family(issued.d1), beforeFamily));
    assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), beforeCredential));
    assert.ok(!failedBody.includes("synthetic replay cleanup D1 unavailable"));
    assert.ok(!logs.join("\n").includes("synthetic replay cleanup D1 unavailable"));
    assert.equal((await ping(issued.env, issued.access)).status, 200);
    const replay = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(replay.status, 400);
    const replayBody = await replay.text();
    assert.ok(isDeepStrictEqual(JSON.parse(replayBody), { error: "invalid_grant" }));
    assertFamilyRevoked(issued.d1);
    assertFamilyLogsClean([issued.code, issued.verifier, issued.access, issued.refresh], `${failedBody}\n${replayBody}`);
  });

  it("revokes D1 for an exchanged authorization code before a provider token-list failure", async () => {
    installFamilyMocks();
    const issued = await issue();
    const current = await rotated(issued.env, issued.refresh);
    const beforeKv = dumpedKv(issued.kv);
    issued.kv.list = async () => { throw new Error("synthetic replay cleanup KV list unavailable"); };
    const response = await exchangeCode(issued.env, issued.code, issued.verifier);
    assert.equal(response.status, 400);
    const body = await response.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "invalid_grant" }));
    assertFamilyRevoked(issued.d1);
    assert.ok(dumpedKv(issued.kv) === beforeKv, "D1 must block surviving KV records when provider cleanup cannot list them");
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    assert.equal((await ping(issued.env, current.access_token)).status, 401);
    await assertRefused(issued.env, issued.refresh);
    await assertRefused(issued.env, current.refresh_token);
    assert.ok(!body.includes("synthetic replay cleanup KV list unavailable"));
    assert.ok(!logs.join("\n").includes("synthetic replay cleanup KV list unavailable"));
    assertFamilyLogsClean([issued.code, issued.verifier, issued.access, issued.refresh,
      current.access_token, current.refresh_token], body);
  });

  it("does not revoke an exchanged code's family for a wrong code or a different authenticated client", async () => {
    installFamilyMocks();
    mock.method(globalThis, "fetch", async (input: unknown) => {
      const clientId = input instanceof Request ? input.url : String(input);
      assert.ok(clientId === CHATGPT_CLIENT_ID || clientId === CLAUDE_CLIENT_ID);
      return Response.json({ ...CIMD, client_id: clientId,
        redirect_uris: [clientId === CLAUDE_CLIENT_ID ? CLAUDE_REDIRECT : CHATGPT_REDIRECT] }, {
        headers: { "Cache-Control": "no-store" },
      });
    });
    const issued = await issue();
    const wrongCode = `${issued.code.slice(0, issued.code.lastIndexOf(":") + 1)}${randomBytes(32).toString("base64url")}`;
    const beforeKv = dumpedKv(issued.kv);
    const beforeFamily = family(issued.d1);
    const beforeCredential = issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all();
    const errors: string[] = [];
    for (const [code, clientId] of [[wrongCode, CHATGPT_CLIENT_ID], [issued.code, CLAUDE_CLIENT_ID]]) {
      const response = await exchangeCode(issued.env, code, issued.verifier, clientId);
      assert.equal(response.status, 400);
      const body = await response.text();
      errors.push(body);
      assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "invalid_grant" }));
      assert.ok(dumpedKv(issued.kv) === beforeKv, "invalid code or client must not change provider records");
      assert.ok(isDeepStrictEqual(family(issued.d1), beforeFamily));
      assert.ok(isDeepStrictEqual(issued.d1.sqlite.prepare("SELECT * FROM participant_credential ORDER BY id").all(), beforeCredential));
    }
    assert.equal((await ping(issued.env, issued.access)).status, 200);
    const current = await rotated(issued.env, issued.refresh);
    assertFamilyLogsClean([issued.code, wrongCode, issued.verifier, issued.access, issued.refresh,
      current.access_token, current.refresh_token], errors.join("\n"));
  });

  it("revokes a refresh family after the provider converts a partial KV write into a 429 response", async () => {
    installFamilyMocks();
    const issued = await issue();
    const failure = failTokenPutAfterGrant(issued.kv);
    const response = await refreshGrant(issued.env, issued.refresh);
    failure.restore();
    assert.ok(failure.happened(), "a provider grant write must persist before the access-token write is rate limited");
    assert.equal(response.status, 429);
    const body = await response.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "temporarily_unavailable" }));
    const state = {
      familyRevoked: family(issued.d1).revoked_at !== null,
      credentialRevoked: issued.d1.sqlite.prepare(
        "SELECT count(*) AS n FROM participant_credential WHERE participant = 'dot' AND revoked_at IS NULL",
      ).get()?.n === 0,
      accessRefused: (await ping(issued.env, issued.access)).status === 401,
      refreshRefused: (await refreshGrant(issued.env, issued.refresh)).status === 400,
    };
    assert.ok(Object.values(state).every(Boolean), "a returned rate-limit response must fail closed after provider mutation");
    assert.ok(!body.includes("KV PUT failed"));
    assert.ok(!logs.join("\n").includes("KV PUT failed"));
    assertFamilyLogsClean([issued.code, issued.verifier, issued.access, issued.refresh], body);
  });

  it("revokes the initial code-exchange family after the provider returns 429 following a grant write", async () => {
    installFamilyMocks();
    const { verifier, challenge } = pkce();
    const { d1, kv, env } = fresh();
    const consented = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge)), env);
    assert.equal(consented.status, 303);
    const location = consented.headers.get("Location");
    assert.ok(location);
    const code = new URL(location).searchParams.get("code");
    assert.ok(code);
    const failure = failTokenPutAfterGrant(kv);
    const response = await exchangeCode(env, code, verifier);
    failure.restore();
    assert.ok(failure.happened(), "initial issuance must persist its grant before the token write is rate limited");
    assert.equal(response.status, 429);
    const body = await response.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "temporarily_unavailable" }));
    const state = {
      revokedFamilyRetained: d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family WHERE revoked_at IS NOT NULL").get()?.n === 1,
      credentialRevoked: d1.sqlite.prepare(
        "SELECT count(*) AS n FROM participant_credential WHERE participant = 'dot' AND revoked_at IS NULL",
      ).get()?.n === 0,
      noAccessRecords: ![...kv.records.keys()].some((key) => key.startsWith("token:")),
      noTokensExposed: !body.includes("access_token") && !body.includes("refresh_token"),
    };
    assert.ok(Object.values(state).every(Boolean), "initial partial issuance must retain D1 revocation and expose no tokens");
    const replay = await exchangeCode(env, code, verifier);
    assert.equal(replay.status, 400);
    const replayBody = await replay.text();
    assert.ok(isDeepStrictEqual(JSON.parse(replayBody), { error: "invalid_grant" }));
    assert.ok(!body.includes("KV PUT failed"));
    assert.ok(!logs.join("\n").includes("KV PUT failed"));
    assertFamilyLogsClean([code, verifier], `${body}\n${replayBody}`);
  });

  it("revokes the family after an uncertain partial provider write and exposes no successor", async () => {
    installFamilyMocks();
    const issued = await issue();
    const originalPut = issued.kv.put.bind(issued.kv);
    let partialWrite = false;
    issued.kv.put = async (...args: Parameters<MemoryKv["put"]>) => {
      await originalPut(...args);
      if (args[0].startsWith("grant:")) {
        partialWrite = true;
        throw new Error("synthetic partial provider write failure");
      }
    };
    const response = await refreshGrant(issued.env, issued.refresh);
    assert.ok(partialWrite, "the failure follows a persisted provider grant write");
    assert.equal(response.status, 500);
    const body = await response.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "internal_error" }));
    assertFamilyRevoked(issued.d1);
    assert.equal((await ping(issued.env, issued.access)).status, 401);
    await assertRefused(issued.env, issued.refresh);
    assert.ok(!body.includes("synthetic partial provider write failure"));
    assert.ok(!logs.join("\n").includes("synthetic partial provider write failure"));
    assertFamilyLogsClean([issued.access, issued.refresh], body);
  });

  it("finishes an admitted rotation when disable races with the provider write and resumes its returned refresh after enable", async () => {
    installFamilyMocks();
    const advance = steppedClock();
    const issued = await issue();
    const originalPut = issued.kv.put.bind(issued.kv);
    let pausedAfterWrite = false;
    issued.kv.put = async (...args: Parameters<MemoryKv["put"]>) => {
      await originalPut(...args);
      if (args[0].startsWith("grant:") && !pausedAfterWrite) {
        issued.d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'dot'").run();
        pausedAfterWrite = true;
      }
    };
    const admitted = await rotated(issued.env, issued.refresh);
    assert.ok(pausedAfterWrite, "pause must occur after provider mutation and before family completion");
    assert.equal(family(issued.d1).revoked_at, null);
    assert.equal(family(issued.d1).pending_id, null);
    assert.ok(family(issued.d1).current_sha256 === tokenHash(admitted.refresh_token));
    const paused = await refreshGrant(issued.env, admitted.refresh_token);
    assert.equal(paused.status, 503);
    assert.equal(paused.headers.get("Retry-After"), "60");
    const body = await paused.text();
    assert.ok(isDeepStrictEqual(JSON.parse(body), { error: "unavailable" }));
    assert.equal((await ping(issued.env, admitted.access_token)).status, 503);
    assert.equal(family(issued.d1).revoked_at, null);
    issued.d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = 'dot'").run();
    advance(BUDGET_MS);
    const resumed = await rotated(issued.env, admitted.refresh_token);
    assert.equal((await ping(issued.env, resumed.access_token)).status, 200);
    assertFamilyLogsClean([issued.access, issued.refresh, admitted.access_token, admitted.refresh_token,
      resumed.access_token, resumed.refresh_token], body);
  });

  it("issues only one successor when two exchanges race with the same authorization code", async () => {
    installFamilyMocks();
    const { verifier, challenge } = pkce();
    const { d1, env } = fresh();
    const consented = await routeRequest(postForm(`${ORIGIN}/authorize`, formBody(challenge)), env);
    assert.equal(consented.status, 303);
    const location = consented.headers.get("Location");
    assert.ok(location);
    const code = new URL(location).searchParams.get("code");
    assert.ok(code);
    const unrelatedToken = `dot:synthetic-unrelated:${randomBytes(32).toString("base64url")}`;
    const exchange = () => routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "authorization_code", code, code_verifier: verifier, token: unrelatedToken,
      client_id: CHATGPT_CLIENT_ID, redirect_uri: CHATGPT_REDIRECT, resource: RESOURCE,
    }).toString()), env);
    d1.holdWritesUntil(2);
    const responses = await Promise.all([exchange(), exchange()]);
    assert.equal(responses.filter((response) => response.status === 200).length, 1);
    const winner = responses.find((response) => response.status === 200);
    const loser = responses.find((response) => response.status !== 200);
    assert.ok(winner && loser);
    assert.ok(loser.status === 400 || loser.status === 503);
    const refusal = await loser.text();
    const tokens = await winner.json() as IssuedTokens;
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_family").get()?.n, 1);
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_token").get()?.n, 1);
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM oauth_refresh_token WHERE token_sha256 = ?")
      .get(tokenHash(unrelatedToken))?.n, 0, "a code exchange must not enroll an unvalidated extra token field");
    assert.ok(family(d1).current_sha256 !== tokenHash(unrelatedToken));
    assert.ok(family(d1).previous_sha256 !== tokenHash(unrelatedToken));
    assert.equal(family(d1).revoked_at, null);
    assert.equal((await ping(env, tokens.access_token)).status, 200);
    const continued = await rotated(env, tokens.refresh_token);
    assertFamilyLogsClean([code, verifier, unrelatedToken, tokens.access_token, tokens.refresh_token,
      continued.access_token, continued.refresh_token], refusal);
  });

  it("refuses refresh for a revoked or inactive grant and still refreshes an active grant", async () => {
    mock.method(globalThis, "fetch", async (input: unknown) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url !== CHATGPT_CLIENT_ID) throw new Error(`unexpected fetch ${url}`);
      return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
    });
    mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });

    const tokenRows = (kv: MemoryKv) => [...kv.records.keys()].filter((key) => key.startsWith("token:")).sort();
    const credentials = (d1: SqliteD1) => d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n;
    const refresh = (env: BridgeEnv, token: string) => routeRequest(postForm(`${ORIGIN}/token`, new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: token,
      client_id: CHATGPT_CLIENT_ID,
    }).toString()), env);
    const secrets: string[] = [];

    const active = await issue();
    secrets.push(active.access, active.refresh);
    const activeRows = tokenRows(active.kv);
    const refreshed = await refresh(active.env, active.refresh);
    assert.equal(refreshed.status, 200);
    const refreshedBody = await refreshed.json() as { access_token?: string; refresh_token?: string };
    assert.equal(typeof refreshedBody.access_token, "string");
    assert.equal(typeof refreshedBody.refresh_token, "string");
    assert.notEqual(refreshedBody.access_token, active.access);
    assert.ok(tokenRows(active.kv).length > activeRows.length);
    assert.ok(await validateDotAccessToken(active.env, refreshedBody.access_token ?? ""));
    secrets.push(refreshedBody.access_token ?? "", refreshedBody.refresh_token ?? "");

    const inactive: [string, (d1: SqliteD1) => void][] = [
      ["revoked", (d1) => {
        d1.sqlite.prepare(
          "UPDATE participant_credential SET revoked_at = ? WHERE participant = 'dot' AND revoked_at IS NULL",
        ).run(OWNER);
      }],
      ["blank revoked_at", (d1) => {
        d1.sqlite.prepare(
          "UPDATE participant_credential SET revoked_at = '' WHERE participant = 'dot' AND revoked_at IS NULL",
        ).run();
      }],
    ];
    for (const [name, revoke] of inactive) {
      const issued = await issue();
      secrets.push(issued.access, issued.refresh);
      revoke(issued.d1);
      const rows = tokenRows(issued.kv);
      const stored = dumpedKv(issued.kv);
      const count = credentials(issued.d1);
      const denied = await refresh(issued.env, issued.refresh);
      assert.equal(denied.status, 400, name);
      const deniedBody = await denied.json();
      assert.deepEqual(deniedBody, { error: "invalid_grant" }, name);
      assert.equal(JSON.stringify(deniedBody).includes(issued.refresh), false, name);
      assert.deepEqual(tokenRows(issued.kv), rows, name);
      assert.equal(dumpedKv(issued.kv), stored, name);
      assert.equal(credentials(issued.d1), count, name);
      const again = await refresh(issued.env, issued.refresh);
      assert.equal(again.status, 400, name);
      assert.deepEqual(await again.json(), { error: "invalid_grant" }, name);
      assert.deepEqual(tokenRows(issued.kv), rows, name);
    }

    const outage = await issue();
    secrets.push(outage.access, outage.refresh);
    const outageRows = tokenRows(outage.kv);
    const outageStored = dumpedKv(outage.kv);
    outage.d1.failRead(new Error("synthetic d1 outage"));
    const down = await refresh(outage.env, outage.refresh);
    assert.equal(down.status, 500);
    const downBody = await down.json() as { error?: string };
    assert.deepEqual(downBody, { error: "internal_error" });
    assert.equal(JSON.stringify(downBody).includes("synthetic d1 outage"), false);
    assert.deepEqual(tokenRows(outage.kv), outageRows);
    assert.equal(dumpedKv(outage.kv), outageStored);
    const recovered = await refresh(outage.env, outage.refresh);
    assert.equal(recovered.status, 200);
    const recoveredBody = await recovered.json() as { access_token?: string; refresh_token?: string };
    assert.equal(typeof recoveredBody.access_token, "string");
    secrets.push(recoveredBody.access_token ?? "", recoveredBody.refresh_token ?? "");
    assertClean(logs.join("\n"), secrets.filter((secret) => secret.length > 0));
    assert.equal(logs.join("\n").includes("synthetic d1 outage"), false);
  });
});
