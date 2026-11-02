/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, it, mock } from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CHATGPT_CLIENT_ID, CHATGPT_REDIRECT, type BridgeEnv } from "../src/oauth-routes.ts";
import {
  AUTHENTICATED_RATE_LIMIT,
  RATE_LIMIT_PERIOD_SECONDS,
  RATE_LIMIT_UNAVAILABLE_REASON,
  UNAUTHENTICATED_RATE_LIMIT,
} from "../src/provisional.ts";
import { enforceAuthenticatedLimit, type RateLimitBinding } from "../src/rate-limit.ts";
import { routeRequest } from "../src/router.ts";
import { SqliteD1 } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";

const ORIGIN = "https://bridge.example";
const EMAIL = "synthetic-owner@example.invalid";
const OWNER = "2026-10-22T00:00:00.000Z";
const GROK = `admrn_gb_${"a".repeat(43)}`;
const GROK_HASH = createHash("sha256").update(GROK).digest("hex");
const DISTINCT_IP = "198.51.100.77";
const CLAIM_CANDIDATE = "w".repeat(43);
const FORM = "application/x-www-form-urlencoded";

const databases: SqliteD1[] = [];
const logs: string[] = [];

function captureLogs(): void {
  mock.method(console, "log", (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  });
  mock.method(console, "error", (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  });
}

function fresh(): { d1: SqliteD1; env: BridgeEnv } {
  const d1 = new SqliteD1();
  databases.push(d1);
  d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run(EMAIL, OWNER);
  d1.sqlite.prepare(`INSERT INTO participant_credential
    (id, participant, kind, token_sha256, owner_claimed_at, created_at)
    VALUES ('credential_grok', 'grok_bot', 'bearer', ?, ?, ?)`).run(GROK_HASH, OWNER, OWNER);
  return {
    d1,
    env: {
      DB: d1.binding(),
      BRIDGE_ORIGIN: ORIGIN,
      OWNER_EMAIL: EMAIL,
      OAUTH_KV: {} as KVNamespace,
      ...permissiveRateLimits(),
    },
  };
}

function originEnv(limits?: { UNAUTHENTICATED_RATE_LIMIT?: RateLimitBinding }): BridgeEnv {
  return { ...fresh().env, ...limits };
}

function countingLimit(allowed: number): { counts: Map<string, number>; binding: RateLimitBinding } {
  const counts = new Map<string, number>();
  return {
    counts,
    binding: {
      limit: async ({ key }) => {
        const next = (counts.get(key) ?? 0) + 1;
        counts.set(key, next);
        return { success: next <= allowed };
      },
    },
  };
}

function authorizeForm(): string {
  return new URLSearchParams({
    connect_code: "c".repeat(43),
    client_id: CHATGPT_CLIENT_ID,
    redirect_uri: CHATGPT_REDIRECT,
    response_type: "code",
    code_challenge: "b".repeat(43),
    code_challenge_method: "S256",
    resource: `${ORIGIN}/mcp`,
    state: "synthetic-state",
  }).toString();
}

function formPost(path: string, ip: string, headers: HeadersInit = {}): Request {
  const requestHeaders = new Headers({ "Content-Type": FORM, "CF-Connecting-IP": ip });
  new Headers(headers).forEach((value, key) => requestHeaders.set(key, value));
  return new Request(`${ORIGIN}${path}`, { method: "POST", headers: requestHeaders, body: "a=b" });
}

function ping(token: string, headers: HeadersInit = {}): Request {
  const requestHeaders = new Headers({ "Content-Type": "application/json", ...Object.fromEntries(new Headers(headers)) });
  requestHeaders.set("Authorization", `Bearer ${token}`);
  return new Request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: requestHeaders,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
  });
}

function events(): { event?: string; reason?: string }[] {
  return logs.flatMap((line) => {
    try {
      const parsed: unknown = JSON.parse(line);
      return typeof parsed === "object" && parsed !== null ? [parsed as { event?: string; reason?: string }] : [];
    } catch {
      return [];
    }
  });
}

afterEach(() => {
  for (const db of databases.splice(0)) db.sqlite.close();
  logs.length = 0;
  mock.restoreAll();
});

describe("native rate limiting", () => {
  it("leaves health, discovery, and unknown paths up when the binding is missing", async () => {
    const health = await routeRequest(new Request(`${ORIGIN}/health`), { BRIDGE_ORIGIN: ORIGIN } as BridgeEnv);
    assert.equal(health.status, 200);
    const missing = await routeRequest(new Request(`${ORIGIN}/other`, { method: "POST" }), { BRIDGE_ORIGIN: ORIGIN } as BridgeEnv);
    assert.equal(missing.status, 404);
    const discovery = await routeRequest(
      new Request(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`),
      { BRIDGE_ORIGIN: ORIGIN } as BridgeEnv,
    );
    assert.equal(discovery.status, 200);
    const metadata = await routeRequest(
      new Request(`${ORIGIN}/.well-known/oauth-authorization-server`),
      { BRIDGE_ORIGIN: ORIGIN } as BridgeEnv,
    );
    assert.equal(metadata.status, 200);
  });

  it("fails closed on a limited route when the binding or the client address is missing", async () => {
    captureLogs();
    const token = await routeRequest(
      formPost("/token", DISTINCT_IP),
      { BRIDGE_ORIGIN: ORIGIN } as BridgeEnv,
    );
    assert.equal(token.status, 503);
    assert.deepEqual(await token.json(), { ok: false, error: RATE_LIMIT_UNAVAILABLE_REASON });
    assert.equal(token.headers.get("Cache-Control"), "no-store");
    const claim = await routeRequest(
      new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: { "Content-Type": "text/plain", "Bootstrap-Secret": CLAIM_CANDIDATE },
      }),
      { BRIDGE_ORIGIN: ORIGIN } as BridgeEnv,
    );
    assert.equal(claim.status, 503);
    const authorize = await routeRequest(
      new Request(`${ORIGIN}/authorize`, {
        method: "POST",
        headers: { "Content-Type": FORM },
        body: authorizeForm(),
      }),
      { BRIDGE_ORIGIN: ORIGIN } as BridgeEnv,
    );
    assert.equal(authorize.status, 503);
    const mcp = await routeRequest(
      new Request(`${ORIGIN}/mcp`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }),
      { BRIDGE_ORIGIN: ORIGIN } as BridgeEnv,
    );
    assert.equal(mcp.status, 503);
    const omitted = await routeRequest(
      new Request(`${ORIGIN}/token`, {
        method: "POST",
        headers: { "Content-Type": FORM, "x-admrn-test-omit-client-ip": "1" },
        body: "a=b",
      }),
      originEnv(permissiveRateLimits()),
    );
    assert.equal(omitted.status, 503);
    assert.equal(logs.join("\n").includes(DISTINCT_IP), false);
    assert.equal(events().some((entry) => entry.event === "rate_limit.unavailable" && entry.reason === RATE_LIMIT_UNAVAILABLE_REASON), true);
  });

  it("fails closed when the binding throws or returns a result that is not a boolean", async () => {
    captureLogs();
    const thrown = new Error("sentinel-limiter-detail");
    const exploded = await routeRequest(
      formPost("/token", DISTINCT_IP),
      originEnv({ UNAUTHENTICATED_RATE_LIMIT: { limit: () => Promise.reject(thrown) } }),
    );
    assert.equal(exploded.status, 503);
    const malformed = await routeRequest(
      new Request(`${ORIGIN}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json; charset=utf-8" },
        body: "{}",
      }),
      originEnv({ UNAUTHENTICATED_RATE_LIMIT: { limit: async () => ({ success: "yes" as unknown as boolean }) } }),
    );
    assert.equal(malformed.status, 503);
    assert.equal(logs.join("\n").includes("sentinel-limiter-detail"), false);
    assert.equal(events().filter((entry) => entry.reason === RATE_LIMIT_UNAVAILABLE_REASON).length >= 2, true);
  });

  it("returns 429 with Retry-After and does not touch D1 when the address is over the limit", async () => {
    captureLogs();
    let touched = false;
    const db = new Proxy({} as D1Database, {
      get() {
        touched = true;
        throw new Error("d1 touched");
      },
    });
    const response = await routeRequest(formPost("/token", DISTINCT_IP), {
      DB: db,
      BRIDGE_ORIGIN: ORIGIN,
      ...permissiveRateLimits(async () => ({ success: false })),
    });
    assert.equal(response.status, 429);
    assert.equal(response.headers.get("Retry-After"), String(RATE_LIMIT_PERIOD_SECONDS));
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.deepEqual(await response.json(), { error: "rate_limited" });
    assert.equal(touched, false);
    assert.equal(events().some((entry) => entry.event === "rate_limited" && entry.reason === "rate_limited"), true);
  });

  it("keys the unauthenticated limit by route and CF-Connecting-IP and then reaches the handler", async () => {
    captureLogs();
    const keys: string[] = [];
    const env = originEnv({
      UNAUTHENTICATED_RATE_LIMIT: {
        limit: async ({ key }) => {
          keys.push(key);
          return { success: true };
        },
      },
    });
    const first = await routeRequest(formPost("/token", "198.51.100.20"), env);
    const second = await routeRequest(formPost("/token", "203.0.113.9"), env);
    const charset = await routeRequest(formPost("/token", "198.51.100.20", { "Content-Type": `${FORM}; charset=UTF-8` }), env);
    assert.deepEqual(keys, [
      "token:ip:198.51.100.20",
      "token:ip:203.0.113.9",
      "token:ip:198.51.100.20",
    ]);
    assert.equal(first.status, 400);
    assert.equal(second.status, 400);
    assert.equal(charset.status, 400);
    assert.equal(logs.join("\n").includes("198.51.100.20"), false);
  });

  it("limits the verified credential after auth and refuses when that binding is missing", async () => {
    captureLogs();
    const { d1, env } = fresh();
    const authKeys: string[] = [];
    const blocked = await routeRequest(ping(GROK), {
      ...env,
      UNAUTHENTICATED_RATE_LIMIT: { limit: async () => ({ success: true }) },
      AUTHENTICATED_RATE_LIMIT: {
        limit: async ({ key }) => {
          authKeys.push(key);
          return { success: false };
        },
      },
    });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get("Retry-After"), String(RATE_LIMIT_PERIOD_SECONDS));
    const digest = createHash("sha256").update(GROK).digest("hex");
    assert.deepEqual(authKeys, [`credential:${digest}`]);
    assert.equal(authKeys[0].includes(GROK), false);
    assert.equal((d1.sqlite.prepare("SELECT COUNT(*) AS n FROM item").get() as { n: number }).n, 0);
    assert.equal(logs.join("\n").includes(GROK), false);
    assert.equal(logs.join("\n").includes(digest), false);

    const { env: open } = fresh();
    const allowed = await routeRequest(ping(GROK), open);
    assert.equal(allowed.status, 200);
    assert.deepEqual(await allowed.json(), { jsonrpc: "2.0", id: 1, result: {} });

    const { env: bare } = fresh();
    const unavailable = await routeRequest(ping(GROK), { ...bare, AUTHENTICATED_RATE_LIMIT: undefined });
    assert.equal(unavailable.status, 503);
    assert.deepEqual(await unavailable.json(), { ok: false, error: RATE_LIMIT_UNAVAILABLE_REASON });

    let authenticated = 0;
    const { env: invalid } = fresh();
    const rejected = await routeRequest(ping(`${GROK}nope`), {
      ...invalid,
      AUTHENTICATED_RATE_LIMIT: {
        limit: async () => {
          authenticated += 1;
          return { success: true };
        },
      },
    });
    assert.equal(rejected.status, 401);
    assert.equal(authenticated, 0);
  });

  it("shares one credential bucket across bearer casing and whitespace", async () => {
    const keys: string[] = [];
    const binding: RateLimitBinding = {
      limit: async ({ key }) => {
        keys.push(key);
        return { success: true };
      },
    };
    const headers = ["bearer X", "Bearer  X", "Bearer X ", "Bearer\tX"];
    for (const header of headers) {
      assert.equal(await enforceAuthenticatedLimit({ AUTHENTICATED_RATE_LIMIT: binding }, header), null);
    }
    const digest = createHash("sha256").update("X").digest("hex");
    assert.deepEqual(keys, headers.map(() => `credential:${digest}`));
    assert.equal(new Set(headers.map((header) => createHash("sha256").update(header).digest("hex"))).size, headers.length);
    assert.equal(keys[0].includes("X"), false);

    let refusedCalls = 0;
    const refused = await enforceAuthenticatedLimit(
      {
        AUTHENTICATED_RATE_LIMIT: {
          limit: async () => {
            refusedCalls += 1;
            return { success: true };
          },
        },
      },
      "Basic X",
    );
    assert.equal(refused?.status, 503);
    assert.equal(refusedCalls, 0);

    const { env } = fresh();
    const routeKeys: string[] = [];
    const limited = {
      ...env,
      AUTHENTICATED_RATE_LIMIT: {
        limit: async ({ key }: { key: string }) => {
          routeKeys.push(key);
          return { success: true };
        },
      },
    };
    for (const authorization of [`bearer ${GROK}`, `Bearer  ${GROK}`]) {
      const response = await routeRequest(
        new Request(`${ORIGIN}/mcp`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: authorization },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
        }),
        limited,
      );
      assert.equal(response.status, 200);
    }
    const grokDigest = createHash("sha256").update(GROK).digest("hex");
    assert.deepEqual(routeKeys, [`credential:${grokDigest}`, `credential:${grokDigest}`]);
    assert.equal(routeKeys[0].includes(GROK), false);
  });

  it("an invalid-method flood does not consume a bucket", async () => {
    const keys: string[] = [];
    const env = originEnv({
      UNAUTHENTICATED_RATE_LIMIT: {
        limit: async ({ key }) => {
          keys.push(key);
          return { success: false };
        },
      },
    });
    const ip = "198.51.100.40";
    const headers = { "CF-Connecting-IP": ip };
    for (let attempt = 0; attempt < UNAUTHENTICATED_RATE_LIMIT + 1; attempt += 1) {
      const flooded = await routeRequest(new Request(`${ORIGIN}/mcp`, { method: "GET", headers }), env);
      assert.equal(flooded.status, 405);
      assert.equal(flooded.headers.get("Allow"), "POST");
    }
    const rejected: Array<{ name: string; request: Request; status: number }> = [
      { name: "put token", request: new Request(`${ORIGIN}/token`, { method: "PUT", headers }), status: 405 },
      { name: "head authorize", request: new Request(`${ORIGIN}/authorize`, { method: "HEAD", headers }), status: 405 },
      { name: "delete mcp", request: new Request(`${ORIGIN}/mcp`, { method: "DELETE", headers }), status: 405 },
      { name: "options claim", request: new Request(`${ORIGIN}/owner/claim`, { method: "OPTIONS", headers }), status: 404 },
      { name: "get claim", request: new Request(`${ORIGIN}/owner/claim`, { headers }), status: 404 },
      {
        name: "mcp text",
        request: new Request(`${ORIGIN}/mcp`, { method: "POST", headers: { ...headers, "Content-Type": "text/plain" }, body: "{}" }),
        status: 415,
      },
      {
        name: "token json",
        request: new Request(`${ORIGIN}/token`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: "{}" }),
        status: 415,
      },
      {
        name: "authorize text",
        request: new Request(`${ORIGIN}/authorize`, { method: "POST", headers: { ...headers, "Content-Type": "text/plain" }, body: "a=b" }),
        status: 415,
      },
      { name: "token query", request: formPost("/token?drop=1", ip), status: 400 },
      { name: "authorize query", request: formPost("/authorize?drop=1", ip), status: 400 },
      { name: "token slash", request: formPost("/token/", ip), status: 404 },
      {
        name: "mcp slash",
        request: new Request(`${ORIGIN}/mcp/`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: "{}" }),
        status: 404,
      },
    ];
    for (const { name, request, status } of rejected) {
      const response = await routeRequest(request, env);
      assert.equal(response.status, status, name);
    }
    const { UNAUTHENTICATED_RATE_LIMIT: _unauthenticated, AUTHENTICATED_RATE_LIMIT: _authenticated, ...unboundEnv } = originEnv();
    const unbound = await routeRequest(new Request(`${ORIGIN}/token`, { method: "GET" }), unboundEnv);
    assert.equal(unbound.status, 405);
    assert.deepEqual(keys, []);
  });

  it("a /mcp flood does not lock /token, /authorize, or /owner/claim", async () => {
    const { counts, binding } = countingLimit(2);
    const env = originEnv({ UNAUTHENTICATED_RATE_LIMIT: binding });
    const ip = "198.51.100.50";
    const mcp = (id: number, contentType = "application/json") => new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: { "CF-Connecting-IP": ip, "Content-Type": contentType, Authorization: `Bearer ${GROK}` },
      body: JSON.stringify({ jsonrpc: "2.0", id, method: "ping" }),
    });
    assert.equal((await routeRequest(mcp(1, "application/json; charset=utf-8"), env)).status, 200);
    assert.equal((await routeRequest(mcp(2), env)).status, 200);
    const blocked = await routeRequest(mcp(3), env);
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get("Retry-After"), String(RATE_LIMIT_PERIOD_SECONDS));

    const token = await routeRequest(formPost("/token", ip), env);
    const authorize = await routeRequest(new Request(`${ORIGIN}/authorize`, { headers: { "CF-Connecting-IP": ip } }), env);
    const claim = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
      method: "POST",
      headers: { "CF-Connecting-IP": ip, "Bootstrap-Secret": CLAIM_CANDIDATE },
    }), env);
    assert.notEqual(token.status, 429);
    assert.notEqual(authorize.status, 429);
    assert.notEqual(claim.status, 429);
    assert.equal(counts.get(`mcp:ip:${ip}`), 3);
    assert.equal(counts.get(`token:ip:${ip}`), 1);
    assert.equal(counts.get(`authorize:ip:${ip}`), undefined);
    assert.equal(counts.get(`owner_claim:ip:${ip}`), 1);
  });

  it("limits /authorize, /token, and /owner/claim on their own keys", async () => {
    const { counts, binding } = countingLimit(1);
    const env = originEnv({ UNAUTHENTICATED_RATE_LIMIT: binding });
    const ip = "198.51.100.60";
    const pairs: Array<{ key: string; request: () => Request }> = [
      { key: "token", request: () => formPost("/token", ip) },
      {
        key: "authorize",
        request: () => new Request(`${ORIGIN}/authorize`, {
          method: "POST",
          headers: { "CF-Connecting-IP": ip, "Content-Type": FORM },
          body: authorizeForm(),
        }),
      },
      { key: "owner_claim", request: () => new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: { "CF-Connecting-IP": ip, "Bootstrap-Secret": CLAIM_CANDIDATE },
      }) },
    ];
    for (const { key, request } of pairs) {
      const allowed = await routeRequest(request(), env);
      assert.notEqual(allowed.status, 429, key);
      assert.notEqual(allowed.status, 503, key);
      const blocked = await routeRequest(request(), env);
      assert.equal(blocked.status, 429, key);
      assert.equal(blocked.headers.get("Retry-After"), String(RATE_LIMIT_PERIOD_SECONDS), key);
      assert.equal(counts.get(`${key}:ip:${ip}`), 2, key);
    }
    const mcp = await routeRequest(ping(GROK, { "CF-Connecting-IP": ip }), env);
    assert.equal(mcp.status, 200);
    assert.equal(counts.get(`mcp:ip:${ip}`), 1);
    assert.equal(counts.get(`token:ip:${ip}`), 2);
  });

  it("invalid or cross-origin GET /authorize does not lock a valid authorize attempt", async () => {
    const { counts, binding } = countingLimit(UNAUTHENTICATED_RATE_LIMIT);
    const env = originEnv({ UNAUTHENTICATED_RATE_LIMIT: binding });
    const ip = "198.51.100.70";
    const challenge = "b".repeat(43);
    const crossOrigin = {
      "CF-Connecting-IP": ip,
      Origin: "https://evil.example",
      "Sec-Fetch-Site": "cross-site",
    };
    const publicQuery = new URLSearchParams({
      client_id: CHATGPT_CLIENT_ID,
      redirect_uri: CHATGPT_REDIRECT,
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: `${ORIGIN}/mcp`,
      state: "synthetic-state",
    });
    const floods = [
      `${ORIGIN}/authorize`,
      `${ORIGIN}/authorize?client_id=${encodeURIComponent(CHATGPT_CLIENT_ID)}`,
      `${ORIGIN}/authorize?${publicQuery}`,
    ];
    for (const url of floods) {
      for (let attempt = 0; attempt < UNAUTHENTICATED_RATE_LIMIT + 1; attempt += 1) {
        const flooded = await routeRequest(new Request(url, { headers: crossOrigin }), env);
        assert.notEqual(flooded.status, 429, url);
      }
    }
    for (let attempt = 0; attempt < UNAUTHENTICATED_RATE_LIMIT + 1; attempt += 1) {
      const invalidPost = await routeRequest(new Request(`${ORIGIN}/authorize`, {
        method: "POST",
        headers: { ...crossOrigin, "Content-Type": FORM },
        body: "a=b",
      }), env);
      assert.notEqual(invalidPost.status, 429);
    }
    assert.equal(counts.get(`authorize:ip:${ip}`) ?? 0, 0);

    const consent = await routeRequest(new Request(`${ORIGIN}/authorize?${publicQuery}`, {
      headers: { "CF-Connecting-IP": ip },
    }), env);
    assert.equal(consent.status, 200);
    assert.match(consent.headers.get("Content-Type") ?? "", /text\/html/);

    const connect = new URLSearchParams(publicQuery);
    connect.set("connect_code", "c".repeat(43));
    const posted = await routeRequest(new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: { "CF-Connecting-IP": ip, "Content-Type": FORM },
      body: connect.toString(),
    }), env);
    assert.notEqual(posted.status, 429);
    assert.equal(counts.get(`authorize:ip:${ip}`), 1);
  });

  it("cross-site POST /authorize does not spend the address bucket", async () => {
    const { counts, binding } = countingLimit(UNAUTHENTICATED_RATE_LIMIT);
    const env = originEnv({ UNAUTHENTICATED_RATE_LIMIT: binding });
    const ip = "198.51.100.71";
    const body = authorizeForm();
    const crossSite = {
      "CF-Connecting-IP": ip,
      "Content-Type": FORM,
      Origin: "https://evil.example",
      "Sec-Fetch-Site": "cross-site",
    };
    for (let attempt = 0; attempt < UNAUTHENTICATED_RATE_LIMIT + 1; attempt += 1) {
      const flooded = await routeRequest(new Request(`${ORIGIN}/authorize`, {
        method: "POST",
        headers: crossSite,
        body,
      }), env);
      assert.equal(flooded.status, 403);
    }
    assert.equal(counts.get(`authorize:ip:${ip}`) ?? 0, 0);

    const sameSite = await routeRequest(new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "CF-Connecting-IP": ip,
        "Content-Type": FORM,
        Origin: "https://other.bridge.example",
        "Sec-Fetch-Site": "same-site",
      },
      body,
    }), env);
    assert.equal(sameSite.status, 403);
    assert.equal(counts.get(`authorize:ip:${ip}`) ?? 0, 0);

    const nullAlone = await routeRequest(new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: { "CF-Connecting-IP": ip, "Content-Type": FORM, Origin: "null" },
      body,
    }), env);
    assert.equal(nullAlone.status, 403);
    assert.equal(counts.get(`authorize:ip:${ip}`) ?? 0, 0);

    const posted = await routeRequest(new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "CF-Connecting-IP": ip,
        "Content-Type": FORM,
        Origin: ORIGIN,
        "Sec-Fetch-Site": "same-origin",
      },
      body,
    }), env);
    assert.notEqual(posted.status, 403);
    assert.notEqual(posted.status, 429);
    assert.equal(counts.get(`authorize:ip:${ip}`), 1);

    const nullSameOrigin = await routeRequest(new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "CF-Connecting-IP": ip,
        "Content-Type": FORM,
        Origin: "null",
        "Sec-Fetch-Site": "same-origin",
      },
      body,
    }), env);
    assert.notEqual(nullSameOrigin.status, 403);
    assert.notEqual(nullSameOrigin.status, 429);
    assert.equal(counts.get(`authorize:ip:${ip}`), 2);
  });

  it("cross-site POST /owner/claim does not spend the address bucket", async () => {
    const previous = Object.getOwnPropertyDescriptor(crypto.subtle, "timingSafeEqual");
    Object.defineProperty(crypto.subtle, "timingSafeEqual", {
      configurable: true,
      value: (left: ArrayBuffer | ArrayBufferView, right: ArrayBuffer | ArrayBufferView) => {
        const bytes = (value: ArrayBuffer | ArrayBufferView) => Buffer.from(
          ArrayBuffer.isView(value)
            ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
            : new Uint8Array(value),
        );
        return timingSafeEqual(bytes(left), bytes(right));
      },
    });
    try {
      const { counts, binding } = countingLimit(UNAUTHENTICATED_RATE_LIMIT);
      const secret = Buffer.alloc(32, 4).toString("base64url");
      const wrong = Buffer.alloc(32, 5).toString("base64url");
      const d1 = new SqliteD1();
      databases.push(d1);
      const env: BridgeEnv = {
        DB: d1.binding(),
        BRIDGE_ORIGIN: ORIGIN,
        OWNER_EMAIL: EMAIL,
        BOOTSTRAP_SECRET: secret,
        ...permissiveRateLimits(),
        UNAUTHENTICATED_RATE_LIMIT: binding,
      };
      const ip = "198.51.100.81";
      const crossSite = {
        "CF-Connecting-IP": ip,
        Origin: "https://evil.example",
        "Sec-Fetch-Site": "cross-site",
      };
      for (let attempt = 0; attempt < UNAUTHENTICATED_RATE_LIMIT + 1; attempt += 1) {
        const flooded = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
          method: "POST",
          headers: crossSite,
        }), env);
        assert.equal(flooded.status, 403);
        assert.deepEqual(await flooded.json(), { error: "cross_site" });
      }
      const malformed = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: { ...crossSite, "Bootstrap-Secret": "short" },
      }), env);
      assert.equal(malformed.status, 403);
      const presented = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: { ...crossSite, "Bootstrap-Secret": secret },
      }), env);
      assert.equal(presented.status, 403);
      assert.equal(counts.get(`owner_claim:ip:${ip}`) ?? 0, 0);
      assert.equal((d1.sqlite.prepare("SELECT COUNT(*) AS n FROM owner_lock").get() as { n: number }).n, 0);

      const sameSite = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: {
          "CF-Connecting-IP": ip,
          Origin: "https://other.bridge.example",
          "Sec-Fetch-Site": "same-site",
        },
      }), env);
      assert.equal(sameSite.status, 403);
      assert.equal(counts.get(`owner_claim:ip:${ip}`) ?? 0, 0);

      const nullOrigin = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: {
          "CF-Connecting-IP": ip,
          Origin: "null",
          "Sec-Fetch-Site": "same-origin",
          "Bootstrap-Secret": secret,
        },
      }), env);
      assert.equal(nullOrigin.status, 403);
      assert.deepEqual(await nullOrigin.json(), { error: "cross_site" });
      assert.equal(counts.get(`owner_claim:ip:${ip}`) ?? 0, 0);
      assert.equal((d1.sqlite.prepare("SELECT COUNT(*) AS n FROM owner_lock").get() as { n: number }).n, 0);

      const missing = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: { "CF-Connecting-IP": ip },
      }), env);
      assert.equal(missing.status, 401);
      assert.deepEqual(await missing.json(), { error: "bootstrap_secret_required" });
      assert.equal(counts.get(`owner_claim:ip:${ip}`) ?? 0, 0);

      const rejected = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: { "CF-Connecting-IP": ip, "Bootstrap-Secret": wrong },
      }), env);
      assert.equal(rejected.status, 401);
      assert.deepEqual(await rejected.json(), { error: "bootstrap_rejected" });
      assert.equal(counts.get(`owner_claim:ip:${ip}`), 1);

      const claimed = await routeRequest(new Request(`${ORIGIN}/owner/claim`, {
        method: "POST",
        headers: {
          "CF-Connecting-IP": "198.51.100.82",
          Origin: ORIGIN,
          "Sec-Fetch-Site": "same-origin",
          "Bootstrap-Secret": secret,
        },
      }), env);
      assert.equal(claimed.status, 201);
      assert.deepEqual(await claimed.json(), { locked: true });
      assert.equal(counts.get("owner_claim:ip:198.51.100.82"), 1);
      assert.equal(
        (d1.sqlite.prepare("SELECT owner_email FROM owner_lock WHERE id = 1").get() as { owner_email: string }).owner_email,
        EMAIL,
      );
    } finally {
      if (previous) Object.defineProperty(crypto.subtle, "timingSafeEqual", previous);
      else Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
    }
  });

  it("pins the example binding to the named rate-limit constants and adds no CPU cap", () => {
    const template = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../wrangler.example.jsonc"), "utf8");
    assert.match(
      template,
      new RegExp(`"name": "UNAUTHENTICATED_RATE_LIMIT"[\\s\\S]*?"limit": ${UNAUTHENTICATED_RATE_LIMIT}[\\s\\S]*?"period": ${RATE_LIMIT_PERIOD_SECONDS}`),
    );
    assert.match(
      template,
      new RegExp(`"name": "AUTHENTICATED_RATE_LIMIT"[\\s\\S]*?"limit": ${AUTHENTICATED_RATE_LIMIT}[\\s\\S]*?"period": ${RATE_LIMIT_PERIOD_SECONDS}`),
    );
    assert.equal(template.includes("cpu_ms"), false);
  });
});
