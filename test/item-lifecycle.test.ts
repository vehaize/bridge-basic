/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { afterEach, describe, it, mock } from "node:test";
import { ACTIVE_ITEM_CAP, ItemLifecycle, ITEM_NOTICE, LifecycleError, RECEIPT_STAMP_CHUNK, ReceiptColumnAbsentError, type Participant } from "../src/item-lifecycle.ts";
import { ITEM_DEADLINE_DEFAULT_MINUTES, ITEM_DEADLINE_MAX_MINUTES, ITEM_DEADLINE_MIN_MINUTES, ITEM_EXPIRING_SOON_MINUTES, RECIPIENT_DECLINE_ENABLED } from "../src/provisional.ts";
import { pinSqliteNow, SqliteD1 } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";
import { routeRequest } from "../src/router.ts";

const databases: SqliteD1[] = [];
const START = Date.parse("2026-01-02T12:00:00.000Z");
const SOURCE = "https://example.com/source";
const OPEN = {
  idempotency_key: "req_original_1234", kind: "task", title: "Research a public topic", body: "Return a short summary.",
  scope: { allowed_sources: [SOURCE], allowed_resources: [] },
};
function setup(skipMigrations: readonly string[] = []) {
  const d1 = new SqliteD1(skipMigrations); databases.push(d1);
  let now = START;
  // Override only the database wall clock used by the production expiry fence.
  // Node SQLite executes the real UPDATE predicate at batch execution time.
  pinSqliteNow(d1.sqlite, () => now);
  return { d1, service: new ItemLifecycle(d1.binding(), () => now), advance: (ms: number) => { now += ms; } };
}
function code(expected: string) {
  return (error: unknown) => error instanceof LifecycleError && error.code === expected && error.message === expected;
}
// Envelope checks hash asynchronously, so wait until a write batch is at the gate before starting a rival.
async function untilWriteBatches(d1: SqliteD1, count: number): Promise<void> {
  while (d1.writeBatches < count) await new Promise((resolve) => setImmediate(resolve));
}
function pageQuery(prepared: string[]): string {
  const sql = [...prepared].reverse().find((entry) => entry.includes("created_at > ?2"));
  if (!sql) throw new Error("page query missing");
  return sql;
}
async function claimed(service: ItemLifecycle, sender: Participant = "dot", key = OPEN.idempotency_key, scope: unknown = OPEN.scope) {
  const opened = await service.openItem(sender, { ...OPEN, idempotency_key: key, scope });
  const recipient: Participant = sender === "dot" ? "grok_bot" : "dot";
  const input = { item_id: opened.item.id };
  await service.claimItem(recipient, input);
  return { input, recipient, sender };
}
async function submitted(service: ItemLifecycle, sender: Participant = "dot") {
  const args = await claimed(service, sender);
  await service.submitResult(args.recipient, { ...args.input, result: "Summary" });
  return args;
}
function key(prefix: string, index: number): string {
  return `req_${prefix}_${index.toString().padStart(8, "0")}`;
}
async function openTo(service: ItemLifecycle, sender: Participant, recipient: Participant, idempotencyKey: string, deadlineMinutes = ITEM_DEADLINE_DEFAULT_MINUTES): Promise<string> {
  const opened = await service.openItem(sender, { ...OPEN, idempotency_key: idempotencyKey, recipient, deadline_minutes: deadlineMinutes });
  return opened.item.id;
}
function deliveredIds(d1: SqliteD1): { stamped: string[]; audited: string[] } {
  return {
    stamped: d1.sqlite.prepare("SELECT id FROM item WHERE delivered_at IS NOT NULL ORDER BY id").all().map((row) => String(row.id)),
    audited: d1.sqlite.prepare("SELECT item_id FROM item_audit WHERE event = 'item_delivered' ORDER BY item_id").all().map((row) => String(row.item_id)),
  };
}
afterEach(() => { for (const db of databases.splice(0)) db.sqlite.close(); mock.restoreAll(); });

describe("internal bidirectional item lifecycle", () => {
  for (const sender of ["dot", "grok_bot"] as const) {
    it(`runs open → claim → submit → review for ${sender}`, async () => {
      const { service, d1 } = setup(), recipient = sender === "dot" ? "grok_bot" : "dot";
      const opened = await service.openItem(sender, OPEN);
      assert.equal(opened.replayed, false);
      assert.equal(opened.item.recipient, recipient);
      assert.equal(opened.notice, ITEM_NOTICE);
      assert.equal(opened.item.owner_approval, "required");
      assert.equal(opened.item.untrusted, true);
      assert.equal(opened.item.result_label, "unverified");
      assert.equal("request_sha256" in opened.item, false);
      const input = { item_id: opened.item.id };
      assert.equal((await service.claimItem(recipient, input)).execute, true);
      assert.equal((await service.claimItem(recipient, input)).execute, false);
      assert.equal((await service.submitResult(recipient, { ...input, result: "A summary", sources: ["https://example.com/source"] })).item.state, "submitted");
      const reviewed = await service.reviewResult(sender, { ...input, decision: "accept", checked: true, note: "Compared the source." });
      assert.equal(reviewed.item.state, "accepted");
      assert.equal(reviewed.item.result_label, "checked_by_requester");
      assert.equal(reviewed.item.owner_approval, "required");
      assert.equal((await service.getItem(sender, input)).item.id, input.item_id);
      assert.ok(d1.sessions.every((value) => value === "first-primary"));
    });
  }

  it("rejects role spoofing, unknown callers, and unknown input properties without writes", async () => {
    const { service, d1 } = setup();
    const opened = await service.openItem("dot", OPEN), input = { item_id: opened.item.id };
    const baseline = d1.sqlite.prepare("SELECT * FROM item").all();
    await assert.rejects(service.claimItem("dot", input), code("not_permitted"));
    await assert.rejects(service.submitResult("dot", { ...input, result: "Spoof" }), code("not_permitted"));
    await assert.rejects(service.reviewResult("grok_bot", { ...input, decision: "accept" }), code("not_permitted"));
    await assert.rejects(service.cancelItem("grok_bot", input), code("not_permitted"));
    await assert.rejects(service.openItem("intruder" as Participant, OPEN), code("not_permitted"));
    await assert.rejects(service.openItem("dot", { ...OPEN, sender: "grok_bot" }), code("invalid_input"));
    await assert.rejects(service.claimItem("grok_bot", { ...input, execute: true }), code("invalid_input"));
    assert.deepEqual(d1.sqlite.prepare("SELECT * FROM item").all(), baseline);
  });

  it("enforces every ordinary transition precondition", async () => {
    const { service } = setup(), opened = await service.openItem("dot", OPEN), input = { item_id: opened.item.id };
    await assert.rejects(service.submitResult("grok_bot", { ...input, result: "Too early" }), code("wrong_state"));
    await assert.rejects(service.reviewResult("dot", { ...input, decision: "accept" }), code("wrong_state"));
    await service.claimItem("grok_bot", input);
    await assert.rejects(service.reviewResult("dot", { ...input, decision: "reject" }), code("wrong_state"));
    await service.submitResult("grok_bot", { ...input, result: "Answer" });
    await assert.rejects(service.cancelItem("dot", input), code("wrong_state"));
    await service.reviewResult("dot", { ...input, decision: "reject", note: "Not responsive" });
    await assert.rejects(service.reviewResult("dot", { ...input, decision: "accept" }), code("wrong_state"));
    assert.equal((await service.claimItem("grok_bot", input)).execute, false);
  });

  it("lets exactly one concurrent claim execute", async () => {
    const { service, d1 } = setup(), opened = await service.openItem("dot", OPEN);
    d1.holdWritesUntil(2);
    const result = await Promise.all([service.claimItem("grok_bot", { item_id: opened.item.id }), service.claimItem("grok_bot", { item_id: opened.item.id })]);
    assert.equal(result.filter((r) => r.execute).length, 1);
    assert.equal(d1.sqlite.prepare("SELECT COUNT(*) AS count FROM item WHERE state = 'claimed'").get()?.count, 1);
  });

  it("replays opens by sender and canonical defaults, conflicting on changed content", async () => {
    const { service } = setup(), first = await service.openItem("dot", OPEN);
    assert.equal(Date.parse(first.item.deadline_at) - Date.parse(first.item.created_at), ITEM_DEADLINE_DEFAULT_MINUTES * 60_000);
    assert.equal((await service.openItem("dot", { ...OPEN, deadline_minutes: ITEM_DEADLINE_DEFAULT_MINUTES })).replayed, true);
    await assert.rejects(service.openItem("dot", { ...OPEN, deadline_minutes: 60 }), code("idempotency_conflict"));
    assert.equal((await service.openItem("grok_bot", OPEN)).replayed, false);
    await assert.rejects(service.openItem("dot", { ...OPEN, body: "Different" }), code("idempotency_conflict"));
    assert.equal((await service.openItem("dot", OPEN)).item.id, first.item.id);
  });

  it("deduplicates concurrent opens and detects conflicting concurrent content", async () => {
    for (const different of [false, true]) {
      const { service, d1 } = setup(); d1.holdWritesUntil(2);
      const result = await Promise.allSettled([service.openItem("dot", OPEN), service.openItem("dot", { ...OPEN, body: different ? "Different" : OPEN.body })]);
      assert.equal(d1.sqlite.prepare("SELECT COUNT(*) AS count FROM item").get()?.count, 1);
      assert.equal(result.filter((r) => r.status === "fulfilled" && !r.value.replayed).length, 1);
      if (different) assert.ok(result.some((r) => r.status === "rejected" && code("idempotency_conflict")(r.reason)));
      else assert.equal(result.filter((r) => r.status === "fulfilled" && r.value.replayed).length, 1);
    }
  });

  it("expires at the exact deadline, frees capacity, and filters effective state", async () => {
    const { service, advance } = setup();
    for (let i = 0; i < 20; i++) await service.openItem("dot", { ...OPEN, idempotency_key: `req_expiry_${i.toString().padStart(8, "0")}`, deadline_minutes: 5 });
    const first = (await service.listItems("grok_bot", { box: "inbox" })).items[0], input = { item_id: first.id };
    advance(300_000);
    assert.equal((await service.getItem("dot", input)).item.state, "expired");
    await assert.rejects(service.claimItem("grok_bot", input), code("deadline_passed"));
    assert.equal((await service.listItems("grok_bot", { box: "inbox", state: "open" })).items.length, 0);
    assert.equal((await service.listItems("grok_bot", { box: "inbox", state: "expired", limit: 20 })).items.length, 20);
    assert.equal((await service.openItem("dot", OPEN)).replayed, false);
  });

  it("does not submit expired claims, but replays their claims without executing", async () => {
    const { service, advance } = setup(), { input, recipient } = await claimed(service);
    advance(ITEM_DEADLINE_DEFAULT_MINUTES * 60_000);
    await assert.rejects(service.submitResult(recipient, { ...input, result: "Late" }), code("deadline_passed"));
    assert.equal((await service.claimItem(recipient, input)).execute, false);
    await assert.rejects(service.cancelItem("dot", input), code("deadline_passed"));
  });

  it("reviews after the deadline and preserves submit/review replay after review", async () => {
    const { service, advance } = setup(), { input, recipient, sender } = await submitted(service);
    advance(86_400_000);
    assert.equal((await service.getItem(sender, input)).item.state, "submitted");
    assert.equal((await service.submitResult(recipient, { ...input, result: "Summary", sources: [] })).replayed, true);
    await service.reviewResult(sender, { ...input, decision: "accept" });
    assert.equal((await service.reviewResult(sender, { ...input, decision: "accept", checked: false })).replayed, true);
    assert.equal((await service.submitResult(recipient, { ...input, result: "Summary" })).replayed, true);
    await assert.rejects(service.submitResult(recipient, { ...input, result: "New" }), code("wrong_state"));
    await assert.rejects(service.reviewResult(sender, { ...input, decision: "accept", note: "New" }), code("wrong_state"));
  });

  it("allows only one conflicting result and one conflicting review to win", async () => {
    const { service, d1 } = setup(), { input, recipient, sender } = await claimed(service);
    d1.holdWritesUntil(2);
    const result = await Promise.allSettled([service.submitResult(recipient, { ...input, result: "A" }), service.submitResult(recipient, { ...input, result: "B" })]);
    assert.equal(result.filter((r) => r.status === "fulfilled").length, 1);
    assert.ok(result.some((r) => r.status === "rejected" && code("wrong_state")(r.reason)));
    const review = await Promise.allSettled([service.reviewResult(sender, { ...input, decision: "accept" }), service.reviewResult(sender, { ...input, decision: "reject" })]);
    assert.equal(review.filter((r) => r.status === "fulfilled").length, 1);
    assert.ok(review.some((r) => r.status === "rejected" && code("wrong_state")(r.reason)));
  });

  it("cancels open or claimed work and makes cancellation terminal and replayable", async () => {
    for (const claim of [false, true]) {
      const { service } = setup(), opened = await service.openItem("dot", OPEN), input = { item_id: opened.item.id };
      if (claim) await service.claimItem("grok_bot", input);
      assert.equal((await service.cancelItem("dot", input)).item.state, "cancelled");
      assert.equal((await service.cancelItem("dot", input)).replayed, true);
      assert.equal((await service.claimItem("grok_bot", input)).execute, false);
      await assert.rejects(service.submitResult("grok_bot", { ...input, result: "Done" }), code("wrong_state"));
      assert.equal((await service.openItem("dot", OPEN)).item.state, "cancelled");
    }
  });

  it("does not execute a claim when a concurrent cancellation wins first", async () => {
    const { service, d1 } = setup(), opened = await service.openItem("dot", OPEN), input = { item_id: opened.item.id };
    d1.holdWritesUntil(2);
    const cancelling = service.cancelItem("dot", input);
    await untilWriteBatches(d1, d1.writeBatches + 1);
    const [cancel, claim] = await Promise.all([cancelling, service.claimItem("grok_bot", input)]);
    assert.equal(cancel.item.state, "cancelled");
    assert.equal(claim.execute, false);
    assert.equal(claim.item.claimed_at, null);
  });

  it("serializes cancel-versus-submit, leaving only one valid transition", async () => {
    const { service, d1 } = setup(), { input, recipient } = await claimed(service);
    d1.holdWritesUntil(2);
    const results = await Promise.allSettled([service.cancelItem("dot", input), service.submitResult(recipient, { ...input, result: "Done" })]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    assert.ok(results.some((r) => r.status === "rejected" && code("wrong_state")(r.reason)));
  });

  it("enforces the active cap atomically and replays before rejecting at the cap", async () => {
    const { service, d1 } = setup();
    for (let i = 0; i < ACTIVE_ITEM_CAP - 1; i++) await service.openItem("dot", { ...OPEN, idempotency_key: `req_capacity_${i.toString().padStart(8, "0")}` });
    d1.holdWritesUntil(2);
    const results = await Promise.allSettled([service.openItem("dot", OPEN), service.openItem("dot", { ...OPEN, idempotency_key: "req_last_competitor" })]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    assert.ok(results.some((r) => r.status === "rejected" && code("too_many_open_items")(r.reason)));
    const replay = await service.openItem("dot", { ...OPEN, idempotency_key: "req_capacity_00000000" });
    assert.equal(replay.replayed, true);
  });

  it("reconciles duplicate keys at the cap rather than misreporting capacity", async () => {
    const { service, d1 } = setup();
    for (let i = 0; i < ACTIVE_ITEM_CAP - 1; i++) await service.openItem("dot", { ...OPEN, idempotency_key: `req_caprace_${i.toString().padStart(8, "0")}` });
    d1.holdWritesUntil(2);
    const results = await Promise.all([service.openItem("dot", OPEN), service.openItem("dot", OPEN)]);
    assert.equal(results.filter((r) => r.replayed).length, 1);
    assert.equal(results[0].item.id, results[1].item.id);
  });

  it("enforces the UTC daily cap, including cancelled items, and resets next day", async () => {
    const { service, advance } = setup();
    for (let i = 0; i < 200; i++) {
      const item = await service.openItem("dot", { ...OPEN, idempotency_key: `req_daily_${i.toString().padStart(8, "0")}` });
      await service.cancelItem("dot", { item_id: item.item.id });
    }
    await assert.rejects(service.openItem("dot", OPEN), code("too_many_open_items"));
    assert.equal((await service.openItem("dot", { ...OPEN, idempotency_key: "req_daily_00000000" })).replayed, true);
    advance(12 * 3_600_000);
    assert.equal((await service.openItem("dot", OPEN)).replayed, false);
  });

  it("uses a fresh single creation-clock sample after an asynchronous replay read", async () => {
    const { d1 } = setup(); let calls = 0;
    const service = new ItemLifecycle(d1.binding(), () => START + (++calls) * 1000);
    const result = await service.openItem("dot", { ...OPEN, deadline_minutes: 5 });
    assert.equal(result.item.created_at, new Date(START + 1000).toISOString());
    assert.equal(Date.parse(result.item.deadline_at) - Date.parse(result.item.created_at), 300_000);
    assert.equal(result.item.created_at, result.item.updated_at);
  });

  it("fences delayed claims, submissions, and cancellation at database execution time", async () => {
    for (const action of ["claim", "submit", "cancel"] as const) {
      const { service, d1, advance } = setup();
      const opened = await service.openItem("dot", { ...OPEN, deadline_minutes: 60 }), input = { item_id: opened.item.id };
      if (action === "submit") await service.claimItem("grok_bot", input);
      advance(3_600_000 - 1);
      d1.holdWritesUntil(2);
      const invoke = () => action === "claim" ? service.claimItem("grok_bot", input)
        : action === "submit" ? service.submitResult("grok_bot", { ...input, result: "Too late" })
          : service.cancelItem("dot", input);
      const first = invoke();
      advance(2);
      const outcomes = await Promise.allSettled([first, invoke()]);
      assert.ok(outcomes.every((outcome) => outcome.status === "rejected" && code("deadline_passed")(outcome.reason)));
      const row = d1.sqlite.prepare("SELECT * FROM item").get();
      assert.equal(row?.state, action === "submit" ? "claimed" : "open");
      assert.equal(row?.submitted_at, null);
      assert.equal(row?.cancelled_at, null);
    }
  });

  it("does not issue execute permission if a successful claim response is already expired", async () => {
    const { service, d1 } = setup(), opened = await service.openItem("dot", { ...OPEN, deadline_minutes: 60 });
    let calls = 0;
    const delayed = new ItemLifecycle(d1.binding(), () => START + 3_600_000 - (calls++ === 0 ? 1 : 0));
    const result = await delayed.claimItem("grok_bot", { item_id: opened.item.id });
    assert.equal(result.item.state, "expired");
    assert.equal(result.execute, false);
  });

  it("uses the real SQLite clock fence even when the injected request clock is stale", async () => {
    const d1 = new SqliteD1(); databases.push(d1);
    const service = new ItemLifecycle(d1.binding(), () => START);
    const opened = await service.openItem("dot", OPEN);
    // START is in the past relative to the real database clock; a stale service
    // clock must not let this claim through. No test clock override here.
    await assert.rejects(service.claimItem("grok_bot", { item_id: opened.item.id }), code("deadline_passed"));
    assert.equal(d1.sqlite.prepare("SELECT claimed_at FROM item").get()?.claimed_at, null);
  });

  it("seeks the participant/state index for ordinary state-filtered pages", async () => {
    const { service, d1 } = setup();
    await service.listItems("dot", { box: "sent", state: "open" });
    const sql = pageQuery(d1.prepared);
    const plan = d1.sqlite.prepare("EXPLAIN QUERY PLAN " + sql).all("dot", "", "", 11, "open", new Date(START).toISOString());
    assert.ok(plan.some((row) => String(row.detail).includes("item_sender_state") && String(row.detail).includes("state=?")));
    await service.listItems("grok_bot", { box: "inbox", state: "accepted" });
    const inboxPlan = d1.sqlite.prepare("EXPLAIN QUERY PLAN " + pageQuery(d1.prepared)).all("grok_bot", "", "", 11, "accepted");
    assert.ok(inboxPlan.some((row) => String(row.detail).includes("item_recipient_state") && String(row.detail).includes("state=?")));
  });

  it("counts Unicode code points, preserves text, and rejects hidden or malformed text", async () => {
    const { service } = setup();
    const exact = { ...OPEN, title: "😀".repeat(120), body: "😀".repeat(800) };
    assert.equal((await service.openItem("dot", exact)).item.title, exact.title);
    for (const title of [" ", "\r", "\u0085", "\ud800", "\u200bhidden", "\u202ehidden", "\u{e0100}", "a".repeat(121), "admrn_gb_" + "a".repeat(43)]) {
      await assert.rejects(service.openItem("dot", { ...OPEN, title }), code("invalid_input"));
    }
    await assert.rejects(service.openItem("dot", { ...OPEN, body: "😀".repeat(801) }), code("invalid_input"));
    assert.equal((await service.openItem("grok_bot", { ...OPEN, title: "A\tB\nC\u200c\u200d" })).item.title, "A\tB\nC\u200c\u200d");
  });

  it("validates deadlines, keys, ids, source grammar, and field bounds", async () => {
    const listed = ["https://example.com/" + "a".repeat(280), "https://sub.example.org/path?q=1#fragment", "https://example.net/"];
    const { service } = setup(), { input, recipient } = await claimed(service, "dot", OPEN.idempotency_key, { allowed_sources: listed, allowed_resources: [] });
    for (const deadline_minutes of [0, 4, 1441, 5.5, null, "60"]) await assert.rejects(service.openItem("dot", { ...OPEN, deadline_minutes }), code("invalid_input"));
    const longest = await service.openItem("dot", { ...OPEN, idempotency_key: "req_longest_deadline", deadline_minutes: ITEM_DEADLINE_MAX_MINUTES });
    assert.equal(Date.parse(longest.item.deadline_at) - Date.parse(longest.item.created_at), ITEM_DEADLINE_MAX_MINUTES * 60_000);
    for (const idempotency_key of ["req_short", "bad_prefix_12345678", "req_" + "a".repeat(65)]) await assert.rejects(service.openItem("dot", { ...OPEN, idempotency_key }), code("invalid_input"));
    for (const item_id of ["item_bad", "req_original_1234", "item_00000000-0000-1000-8000-000000000000"]) await assert.rejects(service.getItem("dot", { item_id }), code("invalid_input"));
    for (const source of ["http://example.com", "https://EXAMPLE.com", "https://localhost", "https://127.0.0.1", "https://[::1]", "https://u@example.com", "https://example.com:443", "https://example.com\\@evil.com", "https://example.com/" + "a".repeat(300)]) {
      await assert.rejects(service.submitResult(recipient, { ...input, result: "Answer", sources: [source] }), code("invalid_input"));
    }
    await assert.rejects(service.submitResult(recipient, { ...input, result: "a".repeat(801) }), code("invalid_input"));
    await assert.rejects(service.submitResult(recipient, { ...input, result: "Answer", sources: Array(4).fill("https://example.com") }), code("invalid_input"));
    // Citations share the allowed_sources grammar, so a host without its path slash is not canonical.
    await assert.rejects(service.submitResult(recipient, { ...input, result: "Answer", sources: ["https://example.net"] }), code("invalid_input"));
    await service.submitResult(recipient, { ...input, result: "a".repeat(800), sources: listed });
  });

  it("requires a note for checked acceptance and never labels rejection or unchecked acceptance verified", async () => {
    const { service } = setup(), { input, sender } = await submitted(service);
    await assert.rejects(service.reviewResult(sender, { ...input, decision: "accept", checked: true }), code("invalid_input"));
    await assert.rejects(service.reviewResult(sender, { ...input, decision: "reject", checked: false }), code("invalid_input"));
    await assert.rejects(service.reviewResult(sender, { ...input, decision: "accept", note: "a".repeat(241) }), code("invalid_input"));
    const reviewed = await service.reviewResult(sender, { ...input, decision: "accept", note: "a".repeat(240) });
    assert.equal(reviewed.item.result_label, "unverified");
    assert.equal(reviewed.item.checked, false);
  });

  it("paginates both boxes with equal timestamps, omitting body and result", async () => {
    const { service } = setup();
    for (let i = 0; i < 5; i++) await service.openItem("dot", { ...OPEN, idempotency_key: `req_paging_${i.toString().padStart(8, "0")}` });
    const first = await service.listItems("grok_bot", { box: "inbox", limit: 2 });
    assert.equal(first.items.length, 2); assert.ok(first.next_cursor);
    const second = await service.listItems("grok_bot", { box: "inbox", limit: 2, cursor: first.next_cursor });
    const last = await service.listItems("dot", { box: "sent", limit: 2, cursor: second.next_cursor });
    assert.equal(last.items.length, 1); assert.equal(last.next_cursor, null);
    const all = [...first.items, ...second.items, ...last.items];
    assert.equal(new Set(all.map((item) => item.id)).size, 5);
    for (const item of all) { assert.equal("body" in item, false); assert.equal("result" in item, false); assert.equal(item.untrusted, true); }
    assert.equal((await service.listItems("dot", { box: "inbox" })).items.length, 0);
    for (const limit of [0, 21, 1.5, null]) await assert.rejects(service.listItems("dot", { box: "sent", limit }), code("invalid_input"));
    await assert.rejects(service.listItems("dot", { box: "sent", cursor: "invalid" }), code("invalid_input"));
  });

  it("keeps inputs out of logs, makes no network calls, and exposes no lifecycle route", async () => {
    const { service, d1 } = setup(), messages: unknown[] = [];
    mock.method(console, "log", (...args: unknown[]) => { messages.push(args); });
    mock.method(console, "error", (...args: unknown[]) => { messages.push(args); });
    mock.method(globalThis, "fetch", () => { throw new Error("No network allowed"); });
    await service.openItem("dot", { ...OPEN, title: "Do not log this title" });
    assert.deepEqual(messages, []);
    const response = await routeRequest(new Request("https://bridge.invalid/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "open_item", arguments: { title: "Do not log this title" } } }),
    }), { DB: d1.binding(), OWNER_EMAIL: "synthetic-owner@example.invalid", BRIDGE_ORIGIN: "https://bridge.invalid", ...permissiveRateLimits() });
    assert.equal(response.status, 401);
    assert.equal((await response.text()).includes("Do not log this title"), false);
    assert.equal(JSON.stringify(messages).includes("Do not log this title"), false);
    assert.equal(d1.sqlite.prepare("SELECT COUNT(*) AS count FROM item").get()?.count, 1);
  });

  it("propagates a failed atomic write without consuming the key or partial transition", async () => {
    const { service, d1 } = setup(); d1.failNextWrite(new Error("synthetic database failure"));
    await assert.rejects(service.openItem("dot", OPEN), /synthetic database failure/);
    assert.equal(d1.sqlite.prepare("SELECT COUNT(*) AS count FROM item").get()?.count, 0);
    assert.equal((await service.openItem("dot", OPEN)).replayed, false);
    const input = { item_id: (await service.openItem("dot", OPEN)).item.id };
    d1.failNextWrite(new Error("synthetic database failure"));
    await assert.rejects(service.claimItem("grok_bot", input), /synthetic database failure/);
    assert.equal((await service.getItem("dot", input)).item.state, "open");
  });

  it("stamps the recipient's first read, repeats pending items, and does not add decline", async () => {
    assert.equal(RECIPIENT_DECLINE_ENABLED, false);
    const { service, d1, advance } = setup();
    const soon = await service.openItem("dot", { ...OPEN, idempotency_key: "req_soon_0001", deadline_minutes: ITEM_EXPIRING_SOON_MINUTES });
    advance(1);
    const later = await service.openItem("dot", { ...OPEN, idempotency_key: "req_later_001", deadline_minutes: ITEM_DEADLINE_DEFAULT_MINUTES });
    advance(1);
    const fromGrok = await service.openItem("grok_bot", { ...OPEN, idempotency_key: "req_from_grok" });
    assert.equal(soon.item.expiring_soon, true);
    assert.equal(later.item.expiring_soon, false);
    assert.equal(soon.item.delivered_at, null);
    const writesBeforeSent = d1.writeBatches;
    const sent = await service.listItems("dot", { box: "sent", state: "expired" });
    assert.equal(d1.writeBatches, writesBeforeSent);
    assert.equal(sent.items.length, 0);
    assert.deepEqual(sent.pending_items.map((item) => item.id), [soon.item.id, later.item.id]);
    for (const item of sent.pending_items) {
      assert.equal("body" in item, false);
      assert.equal("result" in item, false);
      assert.equal(item.delivered_at, null);
    }
    assert.equal((await service.getItem("dot", { item_id: soon.item.id })).item.delivered_at, null);
    const inbox = await service.listItems("grok_bot", { box: "inbox", state: "expired", limit: 1 });
    assert.equal(inbox.items.length, 0);
    assert.deepEqual(inbox.pending_items.map((item) => item.id), [soon.item.id, later.item.id]);
    assert.equal(inbox.pending_items[0]?.expiring_soon, true);
    assert.equal(inbox.pending_items[1]?.expiring_soon, false);
    const stamped = inbox.pending_items[0]?.delivered_at;
    assert.equal(typeof stamped, "string");
    assert.equal(d1.sqlite.prepare("SELECT delivered_at FROM item WHERE id = ?").get(fromGrok.item.id)?.delivered_at, null);
    advance(60_000);
    const again = await service.getItem("grok_bot", { item_id: soon.item.id });
    assert.equal(again.item.delivered_at, stamped);
    assert.equal(d1.sqlite.prepare("SELECT updated_at FROM item WHERE id = ?").get(soon.item.id)?.updated_at, soon.item.updated_at);
    await assert.rejects(service.reviewResult("dot", { item_id: soon.item.id, decision: "decline" }), code("invalid_input"));
    await assert.rejects(service.listItems("dot", { box: "sent", state: "declined" }), code("invalid_input"));
    advance(ITEM_EXPIRING_SOON_MINUTES * 60_000);
    assert.equal((await service.getItem("dot", { item_id: soon.item.id })).item.expiring_soon, false);
    const reviewed = await service.openItem("dot", { ...OPEN, idempotency_key: "req_done_0001", deadline_minutes: 5 });
    await service.claimItem("grok_bot", { item_id: reviewed.item.id });
    await service.submitResult("grok_bot", { item_id: reviewed.item.id, result: "Done" });
    await service.reviewResult("dot", { item_id: reviewed.item.id, decision: "accept" });
    const afterReview = await service.listItems("grok_bot", { box: "inbox" });
    assert.equal(afterReview.pending_items.some((item) => item.id === reviewed.item.id), false);
    assert.equal(afterReview.pending_items.some((item) => item.id === later.item.id), true);
  });

  it("lists a newest short-deadline item behind 20 older rows from another sender", async () => {
    const { service, advance } = setup();
    const older: string[] = [];
    for (let i = 0; i < ACTIVE_ITEM_CAP; i++) {
      older.push(await openTo(service, "dot", "grok_bot", key("older", i)));
      advance(1);
    }
    // The ten oldest rows wait on Dot's review. They are Dot's pending work, not Grok's.
    const waiting = older.slice(0, 10), stillOpen = older.slice(10);
    for (const id of waiting) {
      await service.claimItem("grok_bot", { item_id: id });
      await service.submitResult("grok_bot", { item_id: id, result: "Answer" });
    }
    const urgent = await openTo(service, "claude", "grok_bot", key("urgent", 0), ITEM_DEADLINE_MIN_MINUTES);
    const inbox = await service.listItems("grok_bot", { box: "inbox", limit: 1 });
    assert.deepEqual(inbox.pending_items.map((item) => item.id), [urgent, ...stillOpen]);
    assert.equal(inbox.pending_items[0]?.expiring_soon, true);
    assert.ok(inbox.pending_items.every((item) => item.state === "open"));
    const sent = await service.listItems("dot", { box: "sent" });
    assert.deepEqual(sent.pending_items.map((item) => item.id), older);
    assert.deepEqual(sent.pending_items.map((item) => item.state), [...waiting.map(() => "submitted"), ...stillOpen.map(() => "open")]);
    // The state filter and the history cursor still page every row.
    const filtered = await service.listItems("grok_bot", { box: "inbox", state: "submitted", limit: 20 });
    assert.deepEqual(filtered.items.map((item) => item.id), waiting);
    const first = await service.listItems("grok_bot", { box: "inbox", limit: 20 });
    assert.deepEqual(first.items.map((item) => item.id), older);
    assert.notEqual(first.next_cursor, null);
    const second = await service.listItems("grok_bot", { box: "inbox", limit: 20, cursor: first.next_cursor });
    assert.deepEqual(second.items.map((item) => item.id), [urgent]);
    assert.equal(second.next_cursor, null);
  });

  it("lists all 40 open or claimed inbox rows from two full senders, soonest deadline first", async () => {
    const { service, d1, advance } = setup();
    const fromDot: string[] = [], fromClaude: string[] = [];
    for (let i = 0; i < ACTIVE_ITEM_CAP; i++) {
      fromDot.push(await openTo(service, "dot", "grok_bot", key("dot", i), 120));
      advance(1);
    }
    // Opened later, due sooner.
    for (let i = 0; i < ACTIVE_ITEM_CAP; i++) {
      fromClaude.push(await openTo(service, "claude", "grok_bot", key("claude", i), 60));
      advance(1);
    }
    await assert.rejects(openTo(service, "claude", "grok_bot", key("claude", ACTIVE_ITEM_CAP), 60), code("too_many_open_items"));
    await service.claimItem("grok_bot", { item_id: fromDot[0] });
    const inbox = await service.listItems("grok_bot", { box: "inbox", limit: 1 });
    assert.equal(inbox.items.length, 1);
    assert.deepEqual(inbox.pending_items.map((item) => item.id), [...fromClaude, ...fromDot]);
    assert.equal(inbox.pending_items.find((item) => item.id === fromDot[0])?.state, "claimed");
    for (const item of inbox.pending_items) assert.equal(typeof item.delivered_at, "string");
    const all = [...fromDot, ...fromClaude].sort();
    assert.deepEqual(deliveredIds(d1), { stamped: all, audited: all });
  });

  it("stamps receipts in chunks when the page and pending rows pass one chunk", async () => {
    const { service, d1, advance } = setup();
    // Twenty accepted rows fill the first page. They are not pending.
    const finished: string[] = [];
    for (let i = 0; i < ACTIVE_ITEM_CAP; i++) {
      const id = await openTo(service, "dot", "grok_bot", key("finished", i));
      await service.claimItem("grok_bot", { item_id: id });
      await service.submitResult("grok_bot", { item_id: id, result: "Answer" });
      await service.reviewResult("dot", { item_id: id, decision: "accept" });
      finished.push(id);
      advance(1);
    }
    const pending: string[] = [];
    for (const sender of ["dot", "claude"] as const) {
      for (let i = 0; i < ACTIVE_ITEM_CAP; i++) {
        pending.push(await openTo(service, sender, "grok_bot", key(`${sender}_live`, i)));
        advance(1);
      }
    }
    const ids = [...finished, ...pending];
    assert.ok(ids.length > RECEIPT_STAMP_CHUNK);
    const before = d1.prepared.length;
    const inbox = await service.listItems("grok_bot", { box: "inbox", limit: 20 });
    assert.deepEqual(inbox.items.map((item) => item.id), finished);
    assert.deepEqual(inbox.pending_items.map((item) => item.id), pending);
    const stamps = d1.prepared.slice(before).filter((sql) => sql.startsWith("UPDATE item SET delivered_at"));
    assert.equal(stamps.length, Math.ceil(ids.length / RECEIPT_STAMP_CHUNK));
    for (const item of [...inbox.items, ...inbox.pending_items]) assert.equal(typeof item.delivered_at, "string");
    assert.deepEqual(deliveredIds(d1), { stamped: [...ids].sort(), audited: [...ids].sort() });
    const accepted = await service.listItems("grok_bot", { box: "inbox", state: "accepted", limit: 20 });
    assert.deepEqual(accepted.items.map((item) => item.id), finished);
    assert.equal(accepted.next_cursor, null);
  });

  it("stamps delivered_at on the first getItem and only once when two reads race", async () => {
    const { service, d1 } = setup();
    const opened = await service.openItem("dot", OPEN);
    const input = { item_id: opened.item.id };
    assert.equal(opened.item.delivered_at, null);
    const first = await service.getItem("grok_bot", input);
    assert.equal(typeof first.item.delivered_at, "string");
    assert.equal(d1.sqlite.prepare("SELECT delivered_at FROM item WHERE id = ?").get(input.item_id)?.delivered_at, first.item.delivered_at);
    assert.equal(d1.sqlite.prepare("SELECT updated_at FROM item WHERE id = ?").get(input.item_id)?.updated_at, opened.item.updated_at);
    const repeat = await service.getItem("grok_bot", input);
    assert.equal(repeat.item.delivered_at, first.item.delivered_at);
    assert.equal((await service.getItem("dot", input)).item.delivered_at, first.item.delivered_at);

    const raced = setup();
    const item = await raced.service.openItem("dot", { ...OPEN, idempotency_key: "req_race_stamp" });
    const raceInput = { item_id: item.item.id };
    raced.d1.sqlite.exec(`CREATE TABLE stamp_log (delivered_at TEXT NOT NULL);
      CREATE TRIGGER item_stamp_once AFTER UPDATE OF delivered_at ON item
      WHEN OLD.delivered_at IS NULL AND NEW.delivered_at IS NOT NULL
      BEGIN
        INSERT INTO stamp_log (delivered_at) VALUES (NEW.delivered_at);
      END;`);
    const early = new ItemLifecycle(raced.d1.binding(), () => START);
    const late = new ItemLifecycle(raced.d1.binding(), () => START + 60_000);
    raced.d1.holdWritesUntil(2);
    const reads = await Promise.all([
      early.getItem("grok_bot", raceInput),
      late.getItem("grok_bot", raceInput),
    ]);
    const stamps = raced.d1.sqlite.prepare("SELECT delivered_at FROM stamp_log").all() as { delivered_at: string }[];
    assert.equal(stamps.length, 1);
    assert.equal(reads[0]?.item.delivered_at, stamps[0]?.delivered_at);
    assert.equal(reads[1]?.item.delivered_at, stamps[0]?.delivered_at);
    assert.notEqual(reads[0]?.item.delivered_at, null);
    assert.equal(raced.d1.sqlite.prepare("SELECT updated_at FROM item WHERE id = ?").get(raceInput.item_id)?.updated_at, item.item.updated_at);
    assert.equal(raced.d1.sqlite.prepare("SELECT COUNT(*) AS n FROM item").get()?.n, 1);
  });

  it("fails loudly when migration 0005 has not added delivered_at", async () => {
    // 0006 rebuilds item and copies delivered_at, so a pre-receipt database omits it too.
    const { service, d1 } = setup(["0005_item_receipt.sql", "0006_authority_envelope.sql", "0007_claude_basic_participant.sql"]);
    // Open writes the 0006 envelope columns, so seed the row the way that database stores it.
    const at = new Date(START).toISOString();
    const input = { item_id: "item_cccccccc-cccc-4ccc-8ccc-cccccccccc01" };
    d1.sqlite.prepare(`INSERT INTO item (
      id, sender, recipient, kind, title, body, state, deadline_at, idempotency_key, request_sha256, created_at, updated_at
    ) VALUES (?, 'dot', 'grok_bot', 'task', ?, ?, 'open', '2099-06-01T12:00:00.000Z', ?, 'pre-receipt', ?, ?)`).run(
      input.item_id, OPEN.title, OPEN.body, OPEN.idempotency_key, at, at,
    );
    const before = d1.sqlite.prepare("SELECT id, state, updated_at FROM item WHERE id = ?").get(input.item_id);
    const absent = (error: unknown) =>
      error instanceof ReceiptColumnAbsentError
      && error.message === "item.delivered_at is absent; apply migrations/0005_item_receipt.sql";
    await assert.rejects(service.getItem("grok_bot", input), absent);
    await assert.rejects(service.getItem("dot", input), absent);
    await assert.rejects(service.listItems("grok_bot", { box: "inbox" }), absent);
    assert.equal(d1.prepared.some((sql) => sql.includes(`PRAGMA table_info("item")`)), true);
    assert.equal(d1.prepared.some((sql) => /UPDATE\s+item\s+SET\s+delivered_at/i.test(sql)), false);
    assert.deepEqual(d1.sqlite.prepare("SELECT id, state, updated_at FROM item WHERE id = ?").get(input.item_id), before);
    const columns = d1.sqlite.prepare(`PRAGMA table_info("item")`).all() as { name: string }[];
    assert.equal(columns.some((column) => column.name === "delivered_at"), false);
  });

  it("returns the rebuilt envelope and digest and keeps storage columns off every response", async () => {
    const { d1, service } = setup();
    const opened = await service.openItem("dot", OPEN);
    const stored = d1.sqlite.prepare("SELECT envelope_json, envelope_sha256 FROM item WHERE id = ?").get(opened.item.id) as {
      envelope_json: string;
      envelope_sha256: string;
    };
    const itemKeys = [
      "body", "cancelled_at", "checked", "claimed_at", "created_at", "deadline_at",
      "delivered_at", "envelope", "envelope_sha256", "expiring_soon", "from", "id", "kind", "owner_approval",
      "recipient", "result", "result_label", "review_note", "reviewed_at", "sender",
      "sources", "state", "submitted_at", "title", "untrusted", "updated_at",
    ];
    const summaryKeys = [
      "created_at", "deadline_at", "delivered_at", "envelope_sha256", "expiring_soon", "from", "id",
      "kind", "owner_approval", "result_label", "state", "title", "untrusted",
    ];
    const assertShape = (value: object, keys: string[]): void => {
      assert.deepEqual(Object.keys(value).sort(), keys);
      const encoded = JSON.stringify(value);
      for (const column of ["envelope_json", "request_sha256", "idempotency_key", OPEN.idempotency_key]) assert.equal(encoded.includes(column), false, column);
    };

    assertShape(opened.item, itemKeys);
    assert.deepEqual(opened.item.envelope, JSON.parse(stored.envelope_json));
    assert.equal(opened.item.envelope_sha256, stored.envelope_sha256);
    assert.equal(stored.envelope_sha256, createHash("sha256").update(stored.envelope_json).digest("hex"));

    const fetched = await service.getItem("grok_bot", { item_id: opened.item.id });
    assertShape(fetched.item, itemKeys);
    assert.deepEqual(fetched.item.envelope, opened.item.envelope);

    // Summaries carry the digest and omit the listed URLs.
    for (const box of ["inbox", "sent"] as const) {
      const listed = await service.listItems(box === "inbox" ? "grok_bot" : "dot", { box });
      assert.equal(listed.items.length, 1);
      assertShape(listed.items[0] ?? {}, summaryKeys);
      assertShape(listed.pending_items[0] ?? {}, summaryKeys);
      assert.equal(listed.items[0]?.envelope_sha256, stored.envelope_sha256);
      assert.equal(JSON.stringify(listed).includes(SOURCE), false);
    }

    const claimedItem = await service.claimItem("grok_bot", { item_id: opened.item.id });
    assert.equal(claimedItem.execute, true);
    assertShape(claimedItem.item, itemKeys);
    const submittedItem = await service.submitResult("grok_bot", { item_id: opened.item.id, result: "Answer", sources: [SOURCE] });
    assertShape(submittedItem.item, [...itemKeys, "citations_are_claims_until_independently_checked"].sort());
    assert.equal(submittedItem.item.citations_are_claims_until_independently_checked, true);
    assert.equal(submittedItem.item.result_label, "unverified");
  });
});
