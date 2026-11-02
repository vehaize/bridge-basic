/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, it, mock } from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ItemLifecycle, type CommittedChange } from "../src/item-lifecycle.ts";
import type { BridgeEnv } from "../src/oauth-routes.ts";
import { routeRequest } from "../src/router.ts";
import { deliverWake, type WakeDeps } from "../src/wake.ts";
import { pinSqliteNow, SqliteD1 } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";

const ORIGIN = "https://bridge.example";
const EMAIL = "synthetic-owner@example.invalid";
const OWNER = "2026-10-22T00:00:00.000Z";
const GROK = `admrn_gb_${"b".repeat(43)}`;
const GROK_HASH = createHash("sha256").update(GROK).digest("hex");
const OPEN = {
  idempotency_key: "req_wake_open_1", kind: "task", title: "Public research", body: "Return a short summary.",
  scope: { allowed_sources: [], allowed_resources: [] },
};
const HOOK = "https://receiver.example/hooks/item";
const SECRET_PREFIX = ["wh", "sec_"].join("");

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

function secretBytes(): Buffer {
  return Buffer.alloc(32, 7);
}

function secret(): string {
  return SECRET_PREFIX + secretBytes().toString("base64");
}

function service(onCommit?: (change: CommittedChange) => void): { d1: SqliteD1; lifecycle: ItemLifecycle } {
  const d1 = new SqliteD1();
  databases.push(d1);
  const now = Date.now();
  pinSqliteNow(d1.sqlite, () => now);
  return { d1, lifecycle: new ItemLifecycle(d1.binding(), () => now, onCommit) };
}

function setUrl(d1: SqliteD1, url: string | null): void {
  d1.sqlite.prepare("UPDATE participant SET wake_url = ? WHERE id = 'grok_bot'").run(url);
}

interface Sent {
  url: string;
  init: RequestInit;
}

function recorder(status: number, body = "response-body-stays-unread"): { calls: Sent[]; fetch: WakeDeps["fetch"] } {
  const calls: Sent[] = [];
  const fetchImpl: WakeDeps["fetch"] = async (input, init) => {
    calls.push({ url: input instanceof URL ? input.href : String(input), init: init ?? {} });
    return new Response(body, { status, headers: status >= 300 && status < 400 ? { Location: "https://elsewhere.example/next" } : {} });
  };
  return { calls, fetch: fetchImpl };
}

function grokEnv(d1: SqliteD1): BridgeEnv {
  d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run(EMAIL, OWNER);
  d1.sqlite.prepare(`INSERT INTO participant_credential
    (id, participant, kind, token_sha256, owner_claimed_at, created_at)
    VALUES ('credential_grok', 'grok_bot', 'bearer', ?, ?, ?)`).run(GROK_HASH, OWNER, OWNER);
  return {
    DB: d1.binding(),
    BRIDGE_ORIGIN: ORIGIN,
    OWNER_EMAIL: EMAIL,
    ...permissiveRateLimits(),
    WAKE_SECRET_GROK_BOT: secret(),
  };
}

function context(pending: Promise<unknown>[]): ExecutionContext {
  return {
    waitUntil(promise: Promise<unknown>) {
      pending.push(promise);
    },
    passThroughOnException() {},
    props: {},
  } as ExecutionContext;
}

afterEach(() => {
  for (const db of databases.splice(0)) db.sqlite.close();
  logs.length = 0;
  mock.restoreAll();
});

describe("signed Grok Bot wake", () => {
  it("notifies only a new open, submit, or review, and names the designed participant", async () => {
    const commits: CommittedChange[] = [];
    const { lifecycle } = service((change) => {
      commits.push(change);
    });
    const opened = await lifecycle.openItem("dot", OPEN);
    assert.equal(commits.length, 1);
    assert.deepEqual(commits[0], {
      type: "item.opened",
      itemId: opened.item.id,
      occurredAt: opened.item.created_at,
      participant: "grok_bot",
    });
    assert.equal((await lifecycle.openItem("dot", OPEN)).replayed, true);
    assert.equal(commits.length, 1);
    const input = { item_id: opened.item.id };
    await lifecycle.getItem("grok_bot", input);
    await lifecycle.listItems("grok_bot", { box: "inbox" });
    await lifecycle.claimItem("grok_bot", input);
    assert.equal(commits.length, 1);
    const submitted = await lifecycle.submitResult("grok_bot", { ...input, result: "A public summary" });
    assert.equal(commits.length, 2);
    assert.equal(commits[1]?.type, "item.submitted");
    assert.equal(commits[1]?.participant, "dot");
    assert.equal(commits[1]?.occurredAt, submitted.item.submitted_at);
    assert.equal((await lifecycle.submitResult("grok_bot", { ...input, result: "A public summary" })).replayed, true);
    assert.equal(commits.length, 2);
    const reviewed = await lifecycle.reviewResult("dot", { ...input, decision: "accept" });
    assert.equal(commits.length, 3);
    assert.equal(commits[2]?.type, "item.reviewed");
    assert.equal(commits[2]?.participant, "grok_bot");
    assert.equal(commits[2]?.itemId, opened.item.id);
    assert.equal(commits[2]?.occurredAt, reviewed.item.reviewed_at);
    await lifecycle.reviewResult("dot", { ...input, decision: "accept" });
    const other = await lifecycle.openItem("dot", { ...OPEN, idempotency_key: "req_wake_open_2" });
    await lifecycle.cancelItem("dot", { item_id: other.item.id });
    assert.equal(commits.length, 4);
    assert.equal(commits[3]?.type, "item.opened");
    assert.equal("wake" in opened, false);
    assert.equal(JSON.stringify(opened).includes("receipt acknowledged"), false);
  });

  it("still returns the item when the listener throws", async () => {
    const { lifecycle } = service(() => {
      throw new Error("scheduler exploded");
    });
    const opened = await lifecycle.openItem("dot", { ...OPEN, idempotency_key: "req_wake_throw1" });
    assert.equal(opened.replayed, false);
    assert.equal(opened.item.sender, "dot");
  });

  it("signs one attempt to Grok Bot and refuses the other outcomes without fetching", async () => {
    captureLogs();
    const timeouts: number[] = [];
    mock.method(AbortSignal, "timeout", (ms: number) => {
      timeouts.push(ms);
      return new AbortController().signal;
    });
    const { d1, lifecycle } = service();
    setUrl(d1, HOOK);
    const opened = await lifecycle.openItem("dot", OPEN);
    const change = {
      type: "item.opened" as const,
      itemId: opened.item.id,
      occurredAt: opened.item.created_at,
      participant: "grok_bot" as const,
    };
    const sent = recorder(200);
    const now = () => Date.parse("2026-10-25T00:00:00.000Z");
    const result = await deliverWake(
      { DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() },
      change,
      { fetch: sent.fetch, now },
    );
    assert.equal(result, "sent");
    assert.equal(sent.calls.length, 1);
    assert.equal(sent.calls[0]?.url, HOOK);
    assert.equal(sent.calls[0]?.init.method, "POST");
    assert.equal(sent.calls[0]?.init.redirect, "manual");
    assert.deepEqual(timeouts, [5000]);
    const headers = new Headers(sent.calls[0]?.init.headers);
    const body = String(sent.calls[0]?.init.body);
    const parsed: unknown = JSON.parse(body);
    assert.deepEqual(parsed, { type: "item.opened", item_id: opened.item.id, occurred_at: opened.item.created_at });
    const id = headers.get("webhook-id");
    const timestamp = headers.get("webhook-timestamp");
    assert.equal(timestamp, String(Math.floor(now() / 1000)));
    assert.match(id ?? "", /^msg_[0-9a-f-]{36}$/);
    const mac = createHmac("sha256", secretBytes()).update(`${id}.${timestamp}.${body}`).digest("base64");
    assert.equal(headers.get("webhook-signature"), `v1,${mac}`);
    assert.equal(headers.get("content-type"), "application/json");

    const again = recorder(200);
    await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: again.fetch, now });
    assert.notEqual(new Headers(again.calls[0]?.init.headers).get("webhook-id"), id);

    const refused = recorder(502, "upstream detail");
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: refused.fetch }), "failed");
    assert.equal(refused.calls.length, 1);
    const redirected = recorder(302);
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: redirected.fetch }), "failed");
    assert.equal(redirected.calls.length, 1);

    const exploded = "https://receiver.example/hooks/item network down";
    const throwing: WakeDeps["fetch"] = () => Promise.reject(new Error(exploded));
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: throwing }), "failed");

    const idle: WakeDeps["fetch"] = () => Promise.reject(new Error("should not send"));
    assert.equal(await deliverWake({ DB: d1.binding() }, change, { fetch: idle }), "no_secret");
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: SECRET_PREFIX + Buffer.alloc(16, 1).toString("base64") }, change, { fetch: idle }), "no_secret");
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: "not-a-secret" }, change, { fetch: idle }), "no_secret");
    setUrl(d1, null);
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: idle }), "not_configured");
    setUrl(d1, "   ");
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: idle }), "not_configured");
    for (const bad of ["http://receiver.example/hooks/item", "https://user@receiver.example/hooks/item", "https://receiver.example/hooks/item?x=1", "https://receiver.example/hooks/item#frag"]) {
      setUrl(d1, bad);
      assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: idle }), "failed", bad);
    }
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, { ...change, participant: "dot" }, { fetch: idle }), "not_configured");

    const detail = "sql-detail-must-stay-out";
    d1.failRead(new Error(detail));
    setUrl(d1, HOOK);
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: idle }), "failed");

    const joined = logs.join("\n");
    assert.equal(joined.includes(HOOK), false);
    assert.equal(joined.includes(secret()), false);
    assert.equal(joined.includes("response-body-stays-unread"), false);
    assert.equal(joined.includes("upstream detail"), false);
    assert.equal(joined.includes(exploded), false);
    assert.equal(joined.includes(detail), false);
    assert.equal(joined.includes("receipt acknowledged"), false);
    assert.equal(joined.includes(OPEN.title), false);
    assert.match(joined, /"event":"wake.sent"/);
    assert.match(joined, /"event":"wake.not_configured"/);
    assert.match(joined, /"reason":"sent"/);
    assert.match(joined, /"reason":"failed"/);
    assert.match(joined, /"reason":"no_secret"/);
    assert.match(joined, /"reason":"not_configured"/);
    for (const line of logs) {
      if (!line.includes('"reason":"not_configured"')) continue;
      assert.equal(line.includes('"event":"wake.not_configured"'), true, line);
      assert.equal(line.includes('"event":"wake.failed"'), false, line);
    }
    assert.match(joined, new RegExp(`"item_id":"${opened.item.id}"`));
    assert.match(joined, /"participant":"grok_bot"/);
  });

  it("schedules the wake from /mcp and does not put it on the tool result", async () => {
    captureLogs();
    const { d1 } = service();
    setUrl(d1, HOOK);
    const env = grokEnv(d1);
    let fetches = 0;
    mock.method(globalThis, "fetch", () => {
      fetches += 1;
      return Promise.reject(new Error("fetch is not for the sender"));
    });
    const pending: Promise<unknown>[] = [];
    const response = await routeRequest(new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${GROK}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "open_item", arguments: { ...OPEN, idempotency_key: "req_wake_route1" } },
      }),
    }), env, context(pending));
    assert.equal(response.status, 200);
    const body = await response.json() as { result: { structuredContent: { replayed: boolean; item: { recipient: string } } } };
    assert.equal(body.result.structuredContent.replayed, false);
    assert.equal(body.result.structuredContent.item.recipient, "dot");
    assert.equal(JSON.stringify(body).includes("receipt acknowledged"), false);
    assert.equal(JSON.stringify(body).includes(HOOK), false);
    assert.equal("wake" in body.result.structuredContent, false);
    assert.equal(pending.length, 1);
    assert.equal(await pending[0], "not_configured");
    assert.equal(fetches, 0);
    const replay = await routeRequest(new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: { Authorization: `Bearer ${GROK}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "open_item", arguments: { ...OPEN, idempotency_key: "req_wake_route1" } },
      }),
    }), env, context(pending));
    assert.equal(replay.status, 200);
    assert.equal(pending.length, 1);
    assert.equal(logs.join("\n").includes(HOOK), false);
    assert.equal(logs.join("\n").includes(secret()), false);
    const template = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../wrangler.example.jsonc"), "utf8");
    assert.equal(template.includes("WAKE_SECRET_GROK_BOT"), false);
  });

  it("logs a missing wake configuration as information", async () => {
    const info: string[] = [];
    const errors: string[] = [];
    mock.method(console, "log", (...args: unknown[]) => {
      info.push(args.map(String).join(" "));
    });
    mock.method(console, "error", (...args: unknown[]) => {
      errors.push(args.map(String).join(" "));
    });
    const { d1 } = service();
    const change = {
      type: "item.opened" as const,
      itemId: "item_00000000-0000-4000-8000-000000000018",
      occurredAt: "2026-10-25T00:00:00.000Z",
      participant: "grok_bot" as const,
    };
    const idle: WakeDeps["fetch"] = () => Promise.reject(new Error("should not send"));
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, change, { fetch: idle }), "not_configured");
    assert.match(info.join("\n"), /"event":"wake.not_configured"/);
    assert.match(info.join("\n"), /"reason":"not_configured"/);
    assert.equal(errors.join("\n").includes("not_configured"), false);
    assert.equal(await deliverWake({ DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() }, { ...change, participant: "dot" }, { fetch: idle }), "not_configured");
    assert.equal(errors.join("\n").includes("not_configured"), false);
  });

  it("reports failed and does not fetch when signing throws", async () => {
    const { d1 } = service();
    setUrl(d1, HOOK);
    const calls = recorder(200);
    mock.method(crypto.subtle, "sign", () => Promise.reject(new Error("sign unavailable")));
    const result = await deliverWake(
      { DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() },
      {
        type: "item.opened",
        itemId: "item_00000000-0000-4000-8000-000000000018",
        occurredAt: "2026-10-25T00:00:00.000Z",
        participant: "grok_bot",
      },
      { fetch: calls.fetch },
    );
    assert.equal(result, "failed");
    assert.equal(calls.calls.length, 0);
  });

  it("does not sign a wake when the participant is disabled", async () => {
    const { d1 } = service();
    setUrl(d1, HOOK);
    d1.sqlite.prepare("UPDATE participant SET enabled = 0 WHERE id = 'grok_bot'").run();
    const change = {
      type: "item.opened" as const,
      itemId: "item_00000000-0000-4000-8000-000000000018",
      occurredAt: "2026-10-25T00:00:00.000Z",
      participant: "grok_bot" as const,
    };
    const disabled = recorder(200);
    const withheld = await deliverWake(
      { DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() },
      change,
      { fetch: disabled.fetch },
    );
    assert.equal(withheld, "not_configured");
    assert.equal(disabled.calls.length, 0);

    d1.sqlite.prepare("UPDATE participant SET enabled = 1 WHERE id = 'grok_bot'").run();
    const enabled = recorder(200);
    const sent = await deliverWake(
      { DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() },
      change,
      { fetch: enabled.fetch },
    );
    assert.equal(sent, "sent");
    assert.equal(enabled.calls.length, 1);
    assert.equal(enabled.calls[0]?.url, HOOK);
    assert.match(new Headers(enabled.calls[0]?.init.headers).get("webhook-signature") ?? "", /^v1,/);
  });

  it("does not send a signed wake when the URL is only a query or fragment marker", async () => {
    const { d1 } = service();
    const change = {
      type: "item.opened" as const,
      itemId: "item_00000000-0000-4000-8000-000000000018",
      occurredAt: "2026-10-25T00:00:00.000Z",
      participant: "grok_bot" as const,
    };
    for (const bare of [`${HOOK}?`, `${HOOK}#`]) {
      setUrl(d1, bare);
      const calls = recorder(200);
      const result = await deliverWake(
        { DB: d1.binding(), WAKE_SECRET_GROK_BOT: secret() },
        change,
        { fetch: calls.fetch },
      );
      assert.equal(result, "failed", bare);
      assert.equal(calls.calls.length, 0, bare);
    }
  });
});
