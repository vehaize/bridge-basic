/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { afterEach, describe, it, mock } from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import worker from "../src/index.ts";
import { ItemLifecycle } from "../src/item-lifecycle.ts";
import { RETENTION_CRON, RETENTION_PURGE_DAYS } from "../src/provisional.ts";
import { runRetention } from "../src/retention.ts";
import { SqliteD1 } from "./d1-sqlite.ts";

const DAY_MS = 86_400_000;
const NOW = Date.parse("2099-01-01T00:00:00.000Z");
const CUTOFF = NOW - RETENTION_PURGE_DAYS * DAY_MS;
// item_audit checks the runtime id form, so rows the sweep expires use real item ids.
const ID = {
  futureOpen: "item_00000000-0000-4000-8000-000000000001",
  recentOpen: "item_00000000-0000-4000-8000-000000000002",
  oldOpen: "item_00000000-0000-4000-8000-000000000003",
  oldClaim: "item_00000000-0000-4000-8000-000000000004",
  oldSubmit: "item_00000000-0000-4000-8000-000000000005",
  newSubmit: "item_00000000-0000-4000-8000-000000000006",
  oldAccept: "item_00000000-0000-4000-8000-000000000007",
  newAccept: "item_00000000-0000-4000-8000-000000000008",
  oldReject: "item_00000000-0000-4000-8000-000000000009",
  oldCancel: "item_00000000-0000-4000-8000-000000000010",
  oldExpired: "item_00000000-0000-4000-8000-000000000011",
  newExpired: "item_00000000-0000-4000-8000-000000000012",
} as const;

const databases: SqliteD1[] = [];
const logs: string[] = [];

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function captureLogs(): void {
  mock.method(console, "log", (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  });
  mock.method(console, "error", (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  });
}

function database(): SqliteD1 {
  const d1 = new SqliteD1();
  databases.push(d1);
  return d1;
}

function seed(d1: SqliteD1, id: string, state: string, deadlineMs: number, updatedMs: number, sender = "dot"): void {
  const recipient = sender === "dot" ? "grok_bot" : "dot";
  d1.sqlite.prepare(`INSERT INTO item
    (id, sender, recipient, kind, title, body, state, deadline_at, idempotency_key, request_sha256, created_at, updated_at)
    VALUES (?, ?, ?, 'task', 'Public title', 'Public body', ?, ?, ?, 'hash', ?, ?)`).run(
    id, sender, recipient, state, iso(deadlineMs), `req_${id}`, iso(updatedMs), iso(updatedMs),
  );
}

function expiredAudit(d1: SqliteD1): string[][] {
  return d1.sqlite.prepare("SELECT actor, item_id, occurred_at FROM item_audit WHERE event = 'item_expired' ORDER BY item_id").all()
    .map((entry) => [String(entry.actor), String(entry.item_id), String(entry.occurred_at)]);
}

function row(d1: SqliteD1, id: string): { state: string; updated_at: string; delivered_at: string | null } | undefined {
  return d1.sqlite.prepare("SELECT state, updated_at, delivered_at FROM item WHERE id = ?").get(id) as {
    state: string;
    updated_at: string;
    delivered_at: string | null;
  } | undefined;
}

afterEach(() => {
  for (const db of databases.splice(0)) db.sqlite.close();
  logs.length = 0;
  mock.restoreAll();
});

describe("daily expiry and retention", () => {
  it("stores expiry, then deletes only rows past the cutoff", async () => {
    captureLogs();
    const d1 = database();
    seed(d1, ID.futureOpen, "open", NOW + DAY_MS, CUTOFF - DAY_MS);
    seed(d1, ID.recentOpen, "open", NOW - 1_000, NOW - DAY_MS);
    seed(d1, ID.oldOpen, "open", CUTOFF - 1_000, NOW);
    seed(d1, ID.oldClaim, "claimed", CUTOFF - 1_000, NOW, "grok_bot");
    seed(d1, ID.oldSubmit, "submitted", NOW + DAY_MS, CUTOFF);
    seed(d1, ID.newSubmit, "submitted", NOW + DAY_MS, CUTOFF + 1);
    seed(d1, ID.oldAccept, "accepted", NOW, CUTOFF - 1);
    seed(d1, ID.newAccept, "accepted", NOW, CUTOFF + DAY_MS);
    seed(d1, ID.oldReject, "rejected", NOW, CUTOFF - DAY_MS);
    seed(d1, ID.oldCancel, "cancelled", NOW, CUTOFF);
    seed(d1, ID.oldExpired, "expired", CUTOFF - 1, NOW);
    seed(d1, ID.newExpired, "expired", CUTOFF + DAY_MS, CUTOFF - DAY_MS);

    const count = await runRetention(d1.binding(), NOW);
    assert.equal(count, 7);
    assert.equal(row(d1, ID.futureOpen)?.state, "open");
    assert.equal(row(d1, ID.futureOpen)?.updated_at, iso(CUTOFF - DAY_MS));
    const recent = row(d1, ID.recentOpen);
    assert.equal(recent?.state, "expired");
    assert.equal(recent?.updated_at, iso(NOW - 1_000));
    assert.equal(row(d1, ID.oldOpen), undefined);
    assert.equal(row(d1, ID.oldClaim), undefined);
    assert.equal(row(d1, ID.oldSubmit), undefined);
    assert.equal(row(d1, ID.newSubmit)?.state, "submitted");
    assert.equal(row(d1, ID.oldAccept), undefined);
    assert.equal(row(d1, ID.newAccept)?.state, "accepted");
    assert.equal(row(d1, ID.oldReject), undefined);
    assert.equal(row(d1, ID.oldCancel), undefined);
    assert.equal(row(d1, ID.oldExpired), undefined);
    assert.equal(row(d1, ID.newExpired)?.state, "expired");
    assert.equal(row(d1, ID.newExpired)?.updated_at, iso(CUTOFF - DAY_MS));
    // One item_expired per expired row, at its deadline. The audit rows outlive the purged items.
    assert.deepEqual(expiredAudit(d1), [
      ["system", ID.recentOpen, iso(NOW - 1_000)],
      ["system", ID.oldOpen, iso(CUTOFF - 1_000)],
      ["system", ID.oldClaim, iso(CUTOFF - 1_000)],
    ]);
    assert.equal(await runRetention(d1.binding(), NOW), 0);
    assert.equal(expiredAudit(d1).length, 3);

    const sql = d1.prepared.join("\n");
    assert.match(sql, /deadline_at <= \?1/);
    assert.equal(sql.includes("strftime"), false);
    const joined = logs.join("\n");
    assert.match(joined, /"event":"retention.purged"/);
    assert.match(joined, /"count":7/);
    assert.equal(joined.includes("Public title"), false);
    assert.equal(joined.includes("Public body"), false);
  });

  it("does not let a read move the retention clock", async () => {
    captureLogs();
    const d1 = database();
    const lifecycle = new ItemLifecycle(d1.binding(), () => NOW);
    const opened = await lifecycle.openItem("dot", {
      idempotency_key: "req_retain_read1",
      kind: "task",
      title: "Public title",
      body: "Public body",
      scope: { allowed_sources: [], allowed_resources: [] },
    });
    const read = await lifecycle.getItem("grok_bot", { item_id: opened.item.id });
    assert.equal(typeof read.item.delivered_at, "string");
    assert.equal(read.item.updated_at, opened.item.updated_at);
    await runRetention(d1.binding(), NOW);
    const kept = row(d1, opened.item.id);
    assert.equal(kept?.state, "open");
    assert.equal(kept?.updated_at, opened.item.updated_at);
    assert.equal(kept?.delivered_at, read.item.delivered_at);
    const later = Date.parse(opened.item.deadline_at) + 1;
    await runRetention(d1.binding(), later);
    const expired = row(d1, opened.item.id);
    assert.equal(expired?.state, "expired");
    assert.equal(expired?.updated_at, opened.item.deadline_at);
    assert.equal(expired?.delivered_at, read.item.delivered_at);
    assert.deepEqual(expiredAudit(d1), [["system", opened.item.id, opened.item.deadline_at]]);
    const events = d1.sqlite.prepare("SELECT event FROM item_audit ORDER BY seq").all().map((entry) => String(entry.event));
    assert.deepEqual(events, ["item_opened", "item_delivered", "item_expired"]);
    assert.match(logs.join("\n"), /"event":"retention.audit_pruned"/);
  });

  it("logs a fixed reason when storage fails and the scheduled handler purges by the real clock", async () => {
    captureLogs();
    const failed = database();
    seed(failed, "item_kept_open", "open", Date.now() + DAY_MS, Date.now());
    failed.failNextWrite(new Error("disk-detail-must-stay-out"));
    await assert.rejects(runRetention(failed.binding(), NOW), (error: unknown) => error instanceof Error && error.message === "internal_error");
    assert.equal(row(failed, "item_kept_open")?.state, "open");
    assert.equal(logs.join("\n").includes("disk-detail-must-stay-out"), false);
    assert.match(logs.join("\n"), /"event":"retention.purged"/);
    assert.match(logs.join("\n"), /"reason":"internal_error"/);

    const d1 = database();
    seed(d1, "item_ancient", "submitted", Date.now(), Date.parse("2020-01-01T00:00:00.000Z"));
    seed(d1, "item_live", "open", Date.now() + 7 * DAY_MS, Date.now());
    await worker.scheduled({} as ScheduledController, { DB: d1.binding() } as Env, {} as ExecutionContext);
    assert.equal(row(d1, "item_ancient"), undefined);
    assert.equal(row(d1, "item_live")?.state, "open");
    assert.match(logs.join("\n"), /"count":1/);

    const template = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../wrangler.example.jsonc"), "utf8");
    const crons = template.match(/"crons":\s*\[[\s\S]*?\]/);
    assert.ok(crons);
    assert.equal(crons[0].includes(RETENTION_CRON), true);
    assert.equal(crons[0].includes(","), false);
  });
});
