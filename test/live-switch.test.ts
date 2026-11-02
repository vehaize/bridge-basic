/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { afterEach, describe, it, mock } from "node:test";
import worker from "../src/index.ts";
import type { ItemLifecycle } from "../src/item-lifecycle.ts";
import { LIVE_DISABLED_REASON, LIVE_READ_METHODS, LIVE_READ_TOOLS, liveWritesEnabled } from "../src/live-switch.ts";
import { handleMcpRequest } from "../src/mcp-adapter.ts";
import { CHATGPT_CLIENT_ID, CHATGPT_REDIRECT, type BridgeEnv } from "../src/oauth-routes.ts";
import { routeRequest } from "../src/router.ts";
import { SqliteD1 } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";

const ORIGIN = "https://bridge.invalid";
const EMAIL = "synthetic-owner@example.invalid";
const OWNER = "2026-10-22T00:00:00.000Z";
const GROK = `admrn_gb_${"a".repeat(43)}`;
const GROK_HASH = createHash("sha256").update(GROK).digest("hex");
const OPEN = {
  idempotency_key: "req_live_0001",
  kind: "task",
  title: "Live title",
  body: "Live body",
  scope: { allowed_sources: [], allowed_resources: [] },
};
const ITEM_ID = "item_00000000-0000-4000-8000-000000000000";

const databases: SqliteD1[] = [];

afterEach(() => {
  for (const db of databases.splice(0)) db.sqlite.close();
  mock.restoreAll();
});

function throwingDb(): D1Database {
  return new Proxy({} as D1Database, {
    get() {
      throw new Error("db read");
    },
  });
}

function withLive(base: BridgeEnv, live: string | undefined): BridgeEnv {
  if (live !== undefined) base.LIVE_ENABLED = live;
  return base;
}

function blockedEnv(live: string | undefined): BridgeEnv {
  return withLive({
    DB: throwingDb(),
    BRIDGE_ORIGIN: ORIGIN,
    ...permissiveRateLimits(async () => {
      throw new Error("rate limit spent");
    }),
  }, live);
}

function mcpEnv(live: string | undefined, db: D1Database): BridgeEnv {
  return withLive({
    DB: db,
    BRIDGE_ORIGIN: ORIGIN,
    ...permissiveRateLimits(),
  }, live);
}

function rpc(method: string, params?: unknown): unknown {
  return { jsonrpc: "2.0", id: 1, method, ...(params === undefined ? {} : { params }) };
}

async function callTool(
  d1: SqliteD1,
  live: string | undefined,
  name: string,
  args: unknown,
): Promise<{ status: number; error?: string; isError?: boolean; itemId?: string }> {
  const response = await routeRequest(
    new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${GROK}`,
      },
      body: JSON.stringify(rpc("tools/call", { name, arguments: args })),
    }),
    mcpEnv(live, d1.binding()),
  );
  const body = await response.json() as {
    result?: { isError?: boolean; structuredContent?: { error?: string; item?: { id: string; state?: string } } };
  };
  return {
    status: response.status,
    error: body.result?.structuredContent?.error,
    isError: body.result?.isError,
    itemId: body.result?.structuredContent?.item?.id,
  };
}

function fresh(): SqliteD1 {
  const d1 = new SqliteD1();
  databases.push(d1);
  d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run(EMAIL, OWNER);
  d1.sqlite.prepare(`INSERT INTO participant_credential
    (id, participant, kind, token_sha256, owner_claimed_at, created_at)
    VALUES ('credential_grok', 'grok_bot', 'bearer', ?, ?, ?)`).run(GROK_HASH, OWNER, OWNER);
  return d1;
}

describe("LIVE_ENABLED", () => {
  it("fails closed unless the value is unset or the exact string true", () => {
    assert.equal(liveWritesEnabled(undefined), true);
    assert.equal(liveWritesEnabled("true"), true);
    for (const value of ["false", "", "FALSE", "TRUE", "0", "1", "yes", " true", "true "]) {
      assert.equal(liveWritesEnabled(value), false, value);
    }
  });

  it("does not read LIVE_ENABLED for health, discovery, or GET /authorize", async () => {
    const untouched = new Proxy({} as BridgeEnv, {
      get(_target, key) {
        throw new Error(`read env.${String(key)}`);
      },
    });
    const health = await routeRequest(new Request(`${ORIGIN}/health`), untouched);
    assert.equal(health.status, 200);

    const off = blockedEnv("false");
    const discovery = await routeRequest(
      new Request(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`),
      off,
    );
    assert.equal(discovery.status, 200);
    const metadata = await discovery.json() as { error?: string; resource?: string };
    assert.equal(metadata.error, undefined);
    assert.equal(metadata.resource, `${ORIGIN}/mcp`);

    const authorize = await routeRequest(new Request(`${ORIGIN}/authorize`), off);
    assert.notEqual(authorize.status, 403);
    const page = await authorize.text();
    assert.equal(page.includes(LIVE_DISABLED_REASON), false);
  });

  it("refuses write routes before the rate limit or D1 when writes are off", async () => {
    for (const live of ["false", "yes", "0", ""]) {
      const refused = blockedEnv(live);
      for (const [method, path] of [
        ["POST", "/owner/claim"],
        ["POST", "/authorize"],
        ["POST", "/token"],
        ["GET", "/token"],
      ] as const) {
        const response = await routeRequest(new Request(`${ORIGIN}${path}`, { method }), refused);
        assert.equal(response.status, 403, `${live} ${method} ${path}`);
        assert.equal(response.headers.get("Cache-Control"), "no-store");
        assert.deepEqual(await response.json(), { error: LIVE_DISABLED_REASON });
      }
    }
  });

  it("lets an unset or true write route through", async () => {
    for (const live of [undefined, "true"]) {
      const response = await routeRequest(
        new Request(`${ORIGIN}/owner/claim`, { method: "POST" }),
        blockedEnv(live),
      );
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { error: "bootstrap_secret_required" });
    }
  });

  it("allows a refresh grant when writes are off and blocks every other grant", async () => {
    mock.method(globalThis, "fetch", async (input: unknown) => {
      assert.equal(input instanceof Request ? input.url : String(input), CHATGPT_CLIENT_ID);
      return Response.json({ client_id: CHATGPT_CLIENT_ID, client_name: "Synthetic ChatGPT", redirect_uris: [CHATGPT_REDIRECT], token_endpoint_auth_method: "none" });
    });
    let spent = 0;
    const env = withLive({
      DB: throwingDb(),
      BRIDGE_ORIGIN: ORIGIN,
      OAUTH_KV: {} as KVNamespace,
      ...permissiveRateLimits(async () => {
        spent += 1;
        return { success: true };
      }),
    }, "false");
    const token = (body: string, headers: HeadersInit = { "Content-Type": "application/x-www-form-urlencoded" }) => routeRequest(
      new Request(`${ORIGIN}/token`, { method: "POST", headers, body }),
      env,
    );
    const blocked = [
      "grant_type=authorization_code",
      `grant_type=authorization_code&code=synthetic-auth-code&client_id=${encodeURIComponent(CHATGPT_CLIENT_ID)}`,
      "grant_type=password",
      "grant_type=",
      "grant_type=REFRESH_TOKEN",
      "grant_type=refresh_token&grant_type=authorization_code",
      "grant_type=refresh_token&grant_type=refresh_token",
      "",
    ];
    for (const body of blocked) {
      const response = await token(body);
      assert.equal(response.status, 403, body);
      assert.deepEqual(await response.json(), { error: LIVE_DISABLED_REASON });
    }
    const bare = await routeRequest(new Request(`${ORIGIN}/token`, {
      method: "POST",
      body: "grant_type=refresh_token",
    }), env);
    assert.equal(bare.status, 403);
    const get = await routeRequest(new Request(`${ORIGIN}/token`), env);
    assert.equal(get.status, 403);
    assert.equal(spent, 0);

    const refresh = await token(
      `grant_type=refresh_token&refresh_token=synthetic-refresh-marker&client_id=${encodeURIComponent(CHATGPT_CLIENT_ID)}`,
      { "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" },
    );
    assert.equal(refresh.status, 400);
    assert.deepEqual(await refresh.json(), { error: "invalid_grant" });
    const odd = await token("grant_type=refresh_token&not_a_field=1");
    assert.equal(odd.status, 400);
    assert.deepEqual(await odd.json(), { error: "invalid_request" });
    assert.equal(spent, 2);

    const enabled = withLive({
      DB: throwingDb(),
      BRIDGE_ORIGIN: ORIGIN,
      OAUTH_KV: {} as KVNamespace,
      ...permissiveRateLimits(async () => ({ success: true })),
    }, "true");
    const code = await routeRequest(new Request(`${ORIGIN}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code",
    }), enabled);
    assert.equal(code.status, 401);
    assert.deepEqual(await code.json(), { error: "invalid_client" });
  });

  it("returns HTML for a browser POST /authorize and JSON for other clients", async () => {
    const marker = "synthetic-connect-marker";
    const env = blockedEnv("false");
    const browser = await routeRequest(new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "text/html",
      },
      body: `connect_code=${marker}`,
    }), env);
    assert.equal(browser.status, 403);
    assert.equal(browser.headers.get("Content-Type"), "text/html; charset=utf-8");
    assert.equal(browser.headers.get("Cache-Control"), "no-store");
    assert.equal(browser.headers.get("X-Frame-Options"), "DENY");
    assert.match(browser.headers.get("Content-Security-Policy") ?? "", /default-src 'none'/);
    const page = await browser.text();
    assert.match(page, /live_disabled/);
    assert.equal(page.includes("<script"), false);
    assert.equal(page.includes(marker), false);

    const navigate = await routeRequest(new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        Accept: "application/json",
      },
      body: `connect_code=${marker}`,
    }), env);
    assert.equal(navigate.status, 403);
    assert.equal(navigate.headers.get("Content-Type"), "text/html; charset=utf-8");
    assert.match(await navigate.text(), /live_disabled/);

    const client = await routeRequest(new Request(`${ORIGIN}/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: `connect_code=${marker}`,
    }), env);
    assert.equal(client.status, 403);
    assert.match(client.headers.get("Content-Type") ?? "", /^application\/json/);
    assert.deepEqual(await client.json(), { error: LIVE_DISABLED_REASON });
  });

  it("logs a refused route or tool with its name and reason only", async () => {
    const lines: string[] = [];
    mock.method(console, "log", (...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    });
    const marker = "synthetic-auth-code-marker";
    const response = await routeRequest(new Request(`${ORIGIN}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=authorization_code&code=${marker}`,
    }), blockedEnv("false"));
    assert.equal(response.status, 403);
    const refused = lines.map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((event) => event.event === "live.disabled");
    assert.equal(refused.length, 1);
    assert.deepEqual(Object.keys(refused[0] ?? {}).sort(), ["event", "message", "reason", "route"]);
    assert.equal(refused[0]?.route, "token");
    assert.equal(refused[0]?.reason, LIVE_DISABLED_REASON);
    assert.equal(lines.join("\n").includes(marker), false);

    lines.length = 0;
    const calls: string[] = [];
    const lifecycle = new Proxy({} as ItemLifecycle, {
      get(_target, key) {
        calls.push(String(key));
        throw new Error("lifecycle");
      },
    });
    const tool = await handleMcpRequest(
      new Request(`${ORIGIN}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rpc("tools/call", { name: "open_item", arguments: { idempotency_key: marker } })),
      }),
      { getPrincipal: () => "grok_bot", lifecycle, writesEnabled: false },
    );
    assert.equal(tool.status, 200);
    const toolRefused = lines.map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((event) => event.event === "live.disabled");
    assert.equal(toolRefused.length, 1);
    assert.deepEqual(Object.keys(toolRefused[0] ?? {}).sort(), ["event", "message", "reason", "tool"]);
    assert.equal(toolRefused[0]?.tool, "open_item");
    assert.equal(toolRefused[0]?.reason, LIVE_DISABLED_REASON);
    assert.equal(lines.join("\n").includes(marker), false);
    assert.deepEqual(calls, []);
  });

  it("refuses every registered tool outside the read allowlist when writes are off", async () => {
    assert.deepEqual([...LIVE_READ_TOOLS], ["list_items", "get_item"]);
    assert.deepEqual([...LIVE_READ_METHODS], [
      "initialize",
      "ping",
      "tools/list",
      "notifications/initialized",
    ]);
    const calls: string[] = [];
    const lifecycle = new Proxy({} as ItemLifecycle, {
      get(_target, key) {
        calls.push(String(key));
        throw new Error(`lifecycle.${String(key)}`);
      },
    });
    const send = (method: string, params: unknown, writesEnabled: boolean | undefined) => handleMcpRequest(
      new Request(`${ORIGIN}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rpc(method, params)),
      }),
      { getPrincipal: () => "grok_bot", lifecycle, ...(writesEnabled === undefined ? {} : { writesEnabled }) },
    );
    const listed = await send("tools/list", undefined, false);
    const listedBody = await listed.json() as { result: { tools: { name: string }[] } };
    const names = listedBody.result.tools.map((tool) => tool.name);
    const allow = new Set<string>(["list_items", "get_item"]);
    assert.equal(names.includes("list_items"), true);
    assert.equal(names.includes("get_item"), true);
    for (const name of names) {
      calls.length = 0;
      const response = await send("tools/call", { name, arguments: {} }, false);
      const body = await response.json() as { result: { isError?: boolean; structuredContent: { error?: string } } };
      if (allow.has(name)) {
        assert.equal(body.result.structuredContent.error, "internal_error", name);
        assert.equal(calls.length > 0, true, name);
      } else {
        assert.equal(response.status, 200, name);
        assert.equal(body.result.isError, true, name);
        assert.equal(body.result.structuredContent.error, LIVE_DISABLED_REASON, name);
        assert.deepEqual(calls, [], name);
      }
    }
    calls.length = 0;
    const allowed = await send("tools/call", { name: "open_item", arguments: OPEN }, undefined);
    const allowedBody = await allowed.json() as { result: { structuredContent: { error: string } } };
    assert.equal(allowedBody.result.structuredContent.error, "internal_error");
    assert.equal(calls.length > 0, true);

    for (const method of LIVE_READ_METHODS) {
      if (method === "notifications/initialized") {
        const note = await handleMcpRequest(
          new Request(`${ORIGIN}/mcp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", method }),
          }),
          { getPrincipal: () => "grok_bot", lifecycle, writesEnabled: false },
        );
        assert.equal(note.status, 202, method);
        continue;
      }
      const params = method === "initialize"
        ? { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "synthetic", version: "0" } }
        : undefined;
      const response = await send(method, params, false);
      assert.equal(response.status, 200, method);
      const body = await response.json() as { error?: { message: string } };
      assert.equal(body.error, undefined, method);
    }
  });

  it("blocks MCP writes on the production route and leaves reads working", async () => {
    const d1 = fresh();
    const opened = await callTool(d1, undefined, "open_item", OPEN);
    assert.equal(opened.status, 200);
    assert.equal(opened.error, undefined);
    assert.equal(typeof opened.itemId, "string");
    const itemId = opened.itemId ?? "";
    const before = d1.writeBatches;

    for (const live of ["false", "FALSE"]) {
      const listed = await callTool(d1, live, "list_items", { box: "sent" });
      assert.equal(listed.status, 200);
      assert.equal(listed.error, undefined);
      const read = await callTool(d1, live, "get_item", { item_id: itemId });
      assert.equal(read.status, 200);
      assert.equal(read.error, undefined);
      assert.equal(read.itemId, itemId);
      const names = await registeredToolNames(d1, live);
      const reads = new Set<string>(LIVE_READ_TOOLS);
      assert.equal(names.includes("list_items"), true);
      assert.equal(names.includes("get_item"), true);
      for (const name of names) {
        if (reads.has(name)) continue;
        const args = name === "open_item"
          ? { ...OPEN, idempotency_key: "req_live_0002" }
          : name === "submit_result"
            ? { item_id: itemId, result: "done" }
            : name === "review_result"
              ? { item_id: itemId, decision: "reject" }
              : { item_id: itemId };
        const refused = await callTool(d1, live, name, args);
        assert.equal(refused.status, 200, name);
        assert.equal(refused.isError, true, name);
        assert.equal(refused.error, LIVE_DISABLED_REASON, name);
      }
    }
    assert.equal(d1.writeBatches, before);
    const state = d1.sqlite.prepare("SELECT state FROM item WHERE id = ?").get(itemId) as { state: string };
    assert.equal(state.state, "open");
    const count = d1.sqlite.prepare("SELECT COUNT(*) AS n FROM item").get() as { n: number };
    assert.equal(count.n, 1);

    const again = await callTool(d1, "true", "cancel_item", { item_id: itemId });
    assert.equal(again.error, undefined);
    const cancelled = d1.sqlite.prepare("SELECT state FROM item WHERE id = ?").get(itemId) as { state: string };
    assert.equal(cancelled.state, "cancelled");

    const missing = fresh();
    const refusedOpen = await callTool(missing, "1", "open_item", OPEN);
    assert.equal(refusedOpen.error, LIVE_DISABLED_REASON);
    assert.equal(missing.writeBatches, 0);
    const missingRead = await callTool(missing, "1", "get_item", { item_id: ITEM_ID });
    assert.equal(missingRead.error, "not_found");
  });

  it("still runs scheduled retention when writes are off", async () => {
    const d1 = new SqliteD1();
    databases.push(d1);
    const old = "item_00000000-0000-4000-8000-0000000000aa";
    const open = "item_00000000-0000-4000-8000-0000000000bb";
    const insert = `INSERT INTO item
      (id, sender, recipient, kind, title, body, state, deadline_at, idempotency_key, request_sha256, created_at, updated_at)
      VALUES (?, 'dot', 'grok_bot', 'task', 'Public title', 'Public body', ?, ?, ?, 'hash', ?, ?)`;
    d1.sqlite.prepare(insert).run(
      old, "submitted", "2099-01-01T00:00:00.000Z", "req_old_live", "2020-01-01T00:00:00.000Z", "2020-01-01T00:00:00.000Z",
    );
    d1.sqlite.prepare(insert).run(
      open, "open", "2099-01-02T00:00:00.000Z", "req_open_live", "2098-12-01T00:00:00.000Z", "2098-12-01T00:00:00.000Z",
    );
    const env = new Proxy({ DB: d1.binding() } as Env, {
      get(target, key) {
        if (key === "LIVE_ENABLED") throw new Error("scheduled read LIVE_ENABLED");
        return target[key as keyof Env];
      },
    });
    await worker.scheduled({} as ScheduledController, env, {} as ExecutionContext);
    const kept = d1.sqlite.prepare("SELECT state FROM item WHERE id = ?").get(open) as { state: string } | undefined;
    assert.equal(d1.sqlite.prepare("SELECT id FROM item WHERE id = ?").get(old), undefined);
    assert.equal(kept?.state, "open");
  });
});

async function registeredToolNames(d1: SqliteD1, live: string | undefined): Promise<string[]> {
  const response = await routeRequest(
    new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${GROK}`,
      },
      body: JSON.stringify(rpc("tools/list")),
    }),
    mcpEnv(live, d1.binding()),
  );
  const body = await response.json() as { result?: { tools?: { name: string }[] } };
  return (body.result?.tools ?? []).map((tool) => tool.name);
}
