/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Schema-only checks for migrations/0006_authority_envelope.sql.
 * Applies the file to in-memory SQLite. Does not call the Worker.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { sqlStatements } from "./sql-statements.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATIONS = join(ROOT, "migrations");
const PRIOR = [
  "0001_owner_lock.sql",
  "0002_item_lifecycle.sql",
  "0003_participant_credentials.sql",
  "0004_connect_code.sql",
  "0005_item_receipt.sql",
] as const;
const MIGRATION = "0006_authority_envelope.sql";
const AUDIT_ITEM = "item_01234567-89ab-4cde-8fab-0123456789ab";

const OLD_COLUMNS = [
  "id",
  "sender",
  "recipient",
  "kind",
  "title",
  "body",
  "state",
  "deadline_at",
  "result",
  "sources",
  "review_note",
  "checked",
  "idempotency_key",
  "request_sha256",
  "created_at",
  "claimed_at",
  "submitted_at",
  "reviewed_at",
  "cancelled_at",
  "updated_at",
  "delivered_at",
] as const;

const TRIGGERS = [
  "item_audit_block_delete",
  "item_audit_block_update",
  "item_audit_head_advance",
  "item_audit_head_block_delete",
  "item_audit_head_block_update",
  "item_audit_head_no_replace",
  "item_audit_no_replace",
  "item_audit_one_delivery",
  "item_audit_one_expiry",
  "item_envelope_immutable",
  "item_no_replace",
  "item_no_replace_update",
] as const;

const INDEXES = [
  "item_recipient_created",
  "item_sender_created",
  "item_recipient_state",
  "item_sender_state",
  "item_audit_expiry",
  "item_audit_delivery",
  "item_audit_rejection_cap",
] as const;

const PRESERVED = [
  "owner_lock",
  "bootstrap_secret_spend",
  "participant",
  "participant_credential",
  "connect_code",
] as const;

type SqlValue = string | number | null;
type ItemSeed = Record<(typeof OLD_COLUMNS)[number], SqlValue>;

function execFile(db: DatabaseSync, name: string): void {
  db.exec(readFileSync(join(MIGRATIONS, name), "utf8"));
}

function applyPrior(db: DatabaseSync): void {
  for (const name of PRIOR) execFile(db, name);
}

function item(seed: Partial<ItemSeed> & Pick<ItemSeed, "id" | "state" | "idempotency_key">): ItemSeed {
  const sender = seed.sender ?? "dot";
  return {
    id: seed.id,
    sender,
    recipient: seed.recipient ?? (sender === "dot" ? "grok_bot" : "dot"),
    kind: seed.kind ?? "task",
    title: seed.title ?? `Title ${seed.id}`,
    body: seed.body ?? `Body ${seed.id}`,
    state: seed.state,
    deadline_at: seed.deadline_at ?? "2099-06-01T12:00:00.000Z",
    result: seed.result ?? null,
    sources: seed.sources ?? null,
    review_note: seed.review_note ?? null,
    checked: seed.checked ?? null,
    idempotency_key: seed.idempotency_key,
    request_sha256: seed.request_sha256 ?? `hash-${seed.id}`,
    created_at: seed.created_at ?? "2026-10-01T00:00:00.000Z",
    claimed_at: seed.claimed_at ?? null,
    submitted_at: seed.submitted_at ?? null,
    reviewed_at: seed.reviewed_at ?? null,
    cancelled_at: seed.cancelled_at ?? null,
    updated_at: seed.updated_at ?? "2026-10-02T00:00:00.000Z",
    delivered_at: seed.delivered_at ?? null,
  };
}

const SEEDED: ItemSeed[] = [
  item({ id: "item_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa01", state: "open", idempotency_key: "req_open_future", deadline_at: "2099-06-01T12:00:00.000Z" }),
  item({
    id: "item_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa02",
    state: "open",
    idempotency_key: "req_open_past_deadline",
    deadline_at: "2020-01-15T08:30:00.000Z",
    sender: "grok_bot",
    title: "Past deadline, still open",
    body: "Not expired until the retention sweep.",
  }),
  item({
    id: "item_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa03",
    state: "claimed",
    idempotency_key: "req_claimed",
    claimed_at: "2026-10-01T01:00:00.000Z",
    delivered_at: "2026-10-01T01:05:00.000Z",
    deadline_at: "2026-10-03T00:00:00.000Z",
  }),
  item({
    id: "item_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa04",
    state: "submitted",
    idempotency_key: "req_submitted",
    result: "Result: 100% done.",
    sources: "[\"https://example.com/source\"]",
    claimed_at: "2026-10-01T01:00:00.000Z",
    submitted_at: "2026-10-01T02:00:00.000Z",
    delivered_at: "2026-10-01T01:05:00.000Z",
    deadline_at: "2026-10-04T00:00:00.000Z",
    kind: "question",
  }),
  item({
    id: "item_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa05",
    state: "accepted",
    idempotency_key: "req_accepted",
    result: "Accepted result",
    sources: "[]",
    review_note: "Checked the citation.",
    checked: 1,
    claimed_at: "2026-10-01T01:00:00.000Z",
    submitted_at: "2026-10-01T02:00:00.000Z",
    reviewed_at: "2026-10-01T03:00:00.000Z",
    sender: "grok_bot",
    kind: "proposal",
  }),
  item({
    id: "item_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa06",
    state: "rejected",
    idempotency_key: "req_rejected",
    result: "Rejected result",
    sources: "[\"https://example.com/other\"]",
    review_note: "Not the requested summary.",
    checked: null,
    submitted_at: "2026-10-01T02:00:00.000Z",
    reviewed_at: "2026-10-01T04:00:00.000Z",
  }),
  item({
    id: "item_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa07",
    state: "cancelled",
    idempotency_key: "req_cancelled",
    cancelled_at: "2026-10-01T05:00:00.000Z",
    updated_at: "2026-10-01T05:00:00.000Z",
    deadline_at: "2099-01-01T00:00:00.000Z",
  }),
  item({
    id: "item_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa08",
    state: "expired",
    idempotency_key: "req_expired",
    deadline_at: "2020-06-01T00:00:00.000Z",
    updated_at: "2020-06-01T00:00:00.000Z",
    result: null,
  }),
];

function insertItems(db: DatabaseSync): void {
  const columns = OLD_COLUMNS.join(", ");
  const marks = OLD_COLUMNS.map(() => "?").join(", ");
  const insert = db.prepare(`INSERT INTO item (${columns}) VALUES (${marks})`);
  for (const row of SEEDED) insert.run(...OLD_COLUMNS.map((column) => row[column]));
}

function seedNeighbors(db: DatabaseSync): void {
  db.prepare(
    "INSERT INTO owner_lock (id, owner_email, claimed_at, claim_source) VALUES (1, 'owner@example.com', '2026-10-01T00:00:00.000Z', 'first-boot')",
  ).run();
  db.prepare(
    "INSERT INTO bootstrap_secret_spend (secret_sha256, spent_at) VALUES ('abc123', '2026-10-01T00:00:00.000Z')",
  ).run();
  db.prepare(
    `INSERT INTO participant_credential (id, participant, kind, token_sha256, owner_claimed_at, created_at)
     VALUES ('credential_old', 'grok_bot', 'bearer', ?, '2026-10-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z')`,
  ).run("cd".repeat(32));
  db.prepare(
    `INSERT INTO connect_code (code_sha256, participant, owner_claimed_at, expires_at)
     VALUES (?, 'dot', '2026-10-01T00:00:00.000Z', '2026-10-02T00:00:00.000Z')`,
  ).run("ef".repeat(32));
}

function oldRows(db: DatabaseSync): unknown[] {
  return db.prepare(`SELECT ${OLD_COLUMNS.join(", ")} FROM item ORDER BY id`).all();
}

function neighborRows(db: DatabaseSync): unknown[] {
  const order: Record<(typeof PRESERVED)[number], string> = {
    owner_lock: "id",
    bootstrap_secret_spend: "secret_sha256",
    participant: "id",
    participant_credential: "id",
    connect_code: "code_sha256",
  };
  return PRESERVED.map((table) => ({ table, rows: db.prepare(`SELECT * FROM ${table} ORDER BY ${order[table]}`).all() }));
}

function neighborMaster(db: DatabaseSync): unknown[] {
  const names = PRESERVED.map((table) => `'${table}'`).join(", ");
  return db.prepare(
    `SELECT type, name, tbl_name, sql FROM sqlite_master WHERE tbl_name IN (${names}) ORDER BY tbl_name, type, name`,
  ).all();
}

function normalizeSql(sql: string): string {
  return sql.replace(/\s+/g, " ").trim();
}

function master(db: DatabaseSync): string {
  const rows = db.prepare(
    "SELECT type, name, tbl_name, ifnull(sql, '') AS sql FROM sqlite_master ORDER BY type, name, tbl_name",
  ).all() as { type: string; name: string; tbl_name: string; sql: string }[];
  return rows.map((row) => `${row.type}|${row.name}|${row.tbl_name}|${normalizeSql(row.sql)}`).join("\n");
}

function names(db: DatabaseSync, type: string): string[] {
  return db.prepare("SELECT name FROM sqlite_master WHERE type = ? ORDER BY name").all(type).map((row) => String(row.name));
}

function upgraded(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  applyPrior(db);
  insertItems(db);
  seedNeighbors(db);
  execFile(db, MIGRATION);
  return db;
}

function fresh(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  for (const name of [...PRIOR, MIGRATION]) execFile(db, name);
  return db;
}

function migrationStatements(): string[] {
  return sqlStatements(readFileSync(join(MIGRATIONS, MIGRATION), "utf8"));
}

function statementIndex(statements: string[], marker: string): number {
  const index = statements.findIndex((statement) => statement.includes(marker));
  assert.ok(index >= 0, marker);
  return index;
}

function wrangler(args: string[], cwd: string): { status: number | null; stdout: string; stderr: string } {
  assert.equal(args.includes("--remote"), false);
  assert.equal(args.includes("--local"), true);
  const result = spawnSync(process.execPath, [join(ROOT, "node_modules/wrangler/bin/wrangler.js"), ...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, CI: "1" },
  });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function localRows(config: string, persist: string, sql: string): Record<string, unknown>[] {
  const result = wrangler([
    "d1", "execute", "admrn-bridge",
    "--local",
    "--persist-to", persist,
    "--config", config,
    "--command", sql,
    "--json",
  ], dirname(config));
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const start = result.stdout.indexOf("[");
  assert.ok(start >= 0, result.stdout);
  const parsed = JSON.parse(result.stdout.slice(start)) as { results?: Record<string, unknown>[] }[];
  return parsed[0]?.results ?? [];
}

function fields(value: unknown): Record<string, unknown> {
  assert.ok(value !== null && typeof value === "object");
  return { ...value };
}

function errorMessage(error: unknown): string {
  assert.ok(error instanceof Error);
  return error.message;
}

function throwsMatching(fn: () => void, pattern: RegExp): void {
  assert.throws(fn, (error: unknown) => {
    assert.match(errorMessage(error), pattern);
    return true;
  });
}

describe("migration 0006 authority envelope", () => {
  it("preserves in-flight rows and leaves envelope columns null", () => {
    const db = new DatabaseSync(":memory:");
    applyPrior(db);
    insertItems(db);
    seedNeighbors(db);
    const before = oldRows(db);
    const neighbors = neighborRows(db);
    const preservedSchema = neighborMaster(db);
    assert.equal(before.length, SEEDED.length);
    execFile(db, MIGRATION);

    assert.deepEqual(oldRows(db), before);
    assert.deepEqual(neighborRows(db), neighbors);
    assert.deepEqual(neighborMaster(db), preservedSchema);
    const envelopes = db.prepare("SELECT envelope_json, envelope_sha256 FROM item ORDER BY id").all() as {
      envelope_json: string | null;
      envelope_sha256: string | null;
    }[];
    assert.equal(envelopes.length, SEEDED.length);
    assert.ok(envelopes.every((row) => row.envelope_json === null && row.envelope_sha256 === null));
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit").get()?.n, 0);
    assert.deepEqual(fields(db.prepare("SELECT id, seq FROM item_audit_head").get()), { id: 1, seq: 0 });
    assert.deepEqual(names(db, "trigger"), [...TRIGGERS]);
    for (const index of INDEXES) assert.equal(names(db, "index").includes(index), true);
    const itemSql = String(db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'item'").get()?.sql);
    assert.match(itemSql, /WITHOUT ROWID/);
    assert.equal(readdirSync(MIGRATIONS).some((name) => /0006/i.test(name) && /down/i.test(name)), false);
  });

  it("still allows a state change and an item delete, and blocks envelope updates", () => {
    const db = upgraded();
    const openId = SEEDED[0]?.id;
    if (openId === undefined) throw new Error("missing open item");
    db.prepare(
      "UPDATE item SET state = 'cancelled', cancelled_at = updated_at WHERE id = ? AND state = 'open'",
    ).run(openId);
    assert.equal(db.prepare("SELECT state FROM item WHERE id = ?").get(openId)?.state, "cancelled");
    assert.equal(db.prepare("SELECT envelope_json FROM item WHERE id = ?").get(openId)?.envelope_json, null);

    const expiredId = SEEDED.find((row) => row.state === "expired")?.id;
    if (expiredId === undefined) throw new Error("missing expired item");
    const deleted = db.prepare("DELETE FROM item WHERE id = ?").run(expiredId);
    assert.equal(deleted.changes, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item WHERE id = ?").get(expiredId)?.n, 0);

    const kept = SEEDED[3]?.id;
    if (kept === undefined) throw new Error("missing submitted item");
    const before = db.prepare("SELECT envelope_json, envelope_sha256, state FROM item WHERE id = ?").get(kept);
    throwsMatching(
      () => db.prepare("UPDATE item SET envelope_json = '{}' WHERE id = ?").run(kept),
      /item_envelope_immutable/,
    );
    throwsMatching(
      () => db.prepare("UPDATE item SET envelope_sha256 = ? WHERE id = ?").run("ab".repeat(32), kept),
      /item_envelope_immutable/,
    );
    assert.deepEqual(db.prepare("SELECT envelope_json, envelope_sha256, state FROM item WHERE id = ?").get(kept), before);
  });

  it("rejects audit updates and deletes younger than 90 days, and allows an older delete", () => {
    const db = upgraded();
    const insert = db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?))",
    );
    // One-day margins. The trigger blocks occurred_at >= now-90 days, so an
    // equal timestamp is rejected, but two separate now samples can move that
    // edge by a few milliseconds.
    const young = Number(insert.run("item_opened", "dot", AUDIT_ITEM, "-1 days").lastInsertRowid);
    const old = Number(insert.run("item_claimed", "dot", AUDIT_ITEM, "-91 days").lastInsertRowid);
    assert.deepEqual(fields(db.prepare("SELECT seq FROM item_audit_head WHERE id = 1").get()), { seq: 2 });

    const before = db.prepare("SELECT seq, event, actor, item_id, envelope_sha256, reason, occurred_at FROM item_audit ORDER BY seq").all();
    throwsMatching(() => db.exec("UPDATE item_audit SET actor = 'grok_bot' WHERE seq = 1"), /item_audit_append_only/);
    assert.deepEqual(
      db.prepare("SELECT seq, event, actor, item_id, envelope_sha256, reason, occurred_at FROM item_audit ORDER BY seq").all(),
      before,
    );

    throwsMatching(() => db.prepare("DELETE FROM item_audit WHERE seq = ?").run(young), /item_audit_append_only/);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE seq = ?").get(young)?.n, 1);

    const removed = db.prepare("DELETE FROM item_audit WHERE seq = ?").run(old);
    assert.equal(removed.changes, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE seq = ?").get(old)?.n, 0);
    assert.deepEqual(fields(db.prepare("SELECT id, seq FROM item_audit_head").get()), { id: 1, seq: 2 });
    assert.equal(db.prepare("SELECT count(*) AS n FROM item").get()?.n, SEEDED.length);

    throwsMatching(
      () => db.prepare(
        "INSERT INTO item_audit (seq, event, actor, item_id, occurred_at) VALUES (99, 'item_rejected', 'dot', ?, '2026-10-01T00:00:00.000Z')",
      ).run(AUDIT_ITEM),
      /item_audit_append_only/,
    );
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE seq = 99").get()?.n, 0);
    assert.deepEqual(fields(db.prepare("SELECT seq FROM item_audit_head WHERE id = 1").get()), { seq: 2 });
  });

  it("fails a second apply without changing rows, the audit log, or the schema", () => {
    const db = upgraded();
    db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, envelope_sha256, occurred_at) VALUES ('item_delivered', 'dot', ?, ?, '2026-10-20T00:00:00.000Z')",
    ).run(AUDIT_ITEM, "ab".repeat(32));
    const items = oldRows(db);
    const envelopes = db.prepare("SELECT id, envelope_json, envelope_sha256 FROM item ORDER BY id").all();
    const audit = db.prepare("SELECT * FROM item_audit ORDER BY seq").all();
    const head = db.prepare("SELECT * FROM item_audit_head").all();
    const schema = master(db);
    throwsMatching(() => execFile(db, MIGRATION), /malformed JSON/);
    assert.deepEqual(oldRows(db), items);
    assert.deepEqual(db.prepare("SELECT id, envelope_json, envelope_sha256 FROM item ORDER BY id").all(), envelopes);
    assert.deepEqual(db.prepare("SELECT * FROM item_audit ORDER BY seq").all(), audit);
    assert.deepEqual(db.prepare("SELECT * FROM item_audit_head").all(), head);
    assert.equal(master(db), schema);
  });

  it("matches a fresh 0001-0006 install, including one-statement-at-a-time apply", () => {
    const fromUpgrade = new DatabaseSync(":memory:");
    applyPrior(fromUpgrade);
    insertItems(fromUpgrade);
    execFile(fromUpgrade, MIGRATION);

    const fromFresh = fresh();
    assert.equal(master(fromUpgrade), master(fromFresh));

    const stepped = new DatabaseSync(":memory:");
    for (const name of [...PRIOR, MIGRATION]) {
      for (const statement of sqlStatements(readFileSync(join(MIGRATIONS, name), "utf8"))) stepped.exec(statement);
    }
    assert.equal(master(stepped), master(fromFresh));
    assert.deepEqual(names(stepped, "trigger"), [...TRIGGERS]);
  });

  it("accepts a runtime item id and rejects a malformed one", () => {
    const db = upgraded();
    const insert = db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_opened', 'dot', ?, '2026-10-26T03:05:00.123Z')",
    );
    const valid = [
      "item_01234567-89ab-4cde-8fab-0123456789ab",
      "item_01234567-89ab-4cde-9fab-0123456789ab",
      "item_01234567-89ab-4cde-afab-0123456789ab",
      "item_01234567-89ab-4cde-bfab-0123456789ab",
    ];
    for (const id of valid) assert.equal(insert.run(id).changes, 1);
    const malformed = [
      "item_-1234567-89ab-4cde-8fab-0123456789ab",
      "item_01234567-89AB-4cde-8fab-0123456789ab",
      "item_01234567-89ab-5cde-8fab-0123456789ab",
      "item_01234567-89ab-4cde-cfab-0123456789ab",
      "item_01234567-89ab-4cde-8fab-0123456789a",
      "task_01234567-89ab-4cde-8fab-0123456789ab",
    ];
    for (const id of malformed) throwsMatching(() => insert.run(id), /CHECK constraint failed/);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit").get()?.n, valid.length);
  });

  it("keeps every 0006 GLOB and LIKE pattern within 50 bytes", () => {
    const sql = readFileSync(join(MIGRATIONS, MIGRATION), "utf8");
    const patterns = [...sql.matchAll(/\b(?:GLOB|LIKE)\s+'([^']*)'/gi)].map((match) => match[1] ?? "");
    assert.deepEqual(patterns, ["*[^0-9a-f]*", "*[^0-9a-f-]*", "*[^0-9a-f]*"]);
    for (const pattern of patterns) assert.ok(Buffer.byteLength(pattern) <= 50, pattern);
    const note = readFileSync(join(ROOT, "docs/design/authority-envelope.md"), "utf8");
    const itemIdCheck = [
      "length(item_id) = 41",
      "AND substr(item_id, 1, 5) = 'item_'",
      "AND substr(item_id, 6) NOT GLOB '*[^0-9a-f-]*'",
      "AND substr(item_id, 14, 1) = '-'",
      "AND substr(item_id, 19, 1) = '-'",
      "AND substr(item_id, 24, 1) = '-'",
      "AND substr(item_id, 29, 1) = '-'",
      "AND substr(item_id, 20, 1) = '4'",
      "AND substr(item_id, 25, 1) IN ('8', '9', 'a', 'b')",
      "AND length(replace(substr(item_id, 6), '-', '')) = 32",
    ].join("\n    ");
    assert.equal(sql.includes(itemIdCheck), true);
    assert.equal(note.includes(itemIdCheck), true);
    assert.equal(note.includes("item_[0-9a-f][0-9a-f]"), false);
  });

  it("accepts only the strftime UTC form for occurred_at", () => {
    const db = upgraded();
    const insert = db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_opened', 'dot', ?, ?)",
    );
    const now = new Date().toISOString();
    assert.equal(now.length, 24);
    const valid = [
      now,
      "2020-01-01T00:00:00.000Z",
      "2026-10-26T03:05:00.123Z",
      "2026-10-01T00:00:00.000Z",
      "2026-10-28T23:59:59.999Z",
      "9999-12-31T23:59:59.999Z",
    ];
    for (const value of valid) assert.equal(insert.run(AUDIT_ITEM, value).changes, 1);
    const generated = db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_claimed', 'dot', ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-91 days'))",
    ).run(AUDIT_ITEM);
    assert.equal(generated.changes, 1);

    const malformed = [
      "0",
      "2020-01-01",
      "2026-10-26T03:05:00Z",
      "2026-10-26T03:05:00.123",
      "2026-02-31T00:00:00.000Z",
      "2026-02-30T00:00:00.000Z",
      "2026-10-26T03:05:00.123z",
      "0000-00-00T00:00:00.000Z",
      "2026-13-01T00:00:00.000Z",
      "2026-10-26T00:00:60.000Z",
      "2026-10-01T24:30:00.000Z",
      "2026-10-28T24:00:00.000Z",
      "2019-12-31T23:59:59.999Z",
      "0001-01-01T00:00:00.000Z",
    ];
    for (const value of malformed) {
      throwsMatching(() => insert.run(AUDIT_ITEM, value), /CHECK constraint failed/);
    }
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit").get()?.n, valid.length + 1);

    const source = readFileSync(join(MIGRATIONS, MIGRATION), "utf8");
    const note = readFileSync(join(ROOT, "docs/design/authority-envelope.md"), "utf8");
    const check = [
      "length(occurred_at) = 24",
      "AND occurred_at IS strftime('%Y-%m-%dT%H:%M:%fZ', occurred_at)",
      "AND substr(occurred_at, 12, 2) < '24'",
      "AND occurred_at >= '2020-01-01T00:00:00.000Z'",
    ].join("\n      ");
    assert.equal(source.includes(check), true);
    assert.equal(note.includes(check), true);
    assert.equal(source.includes("occurred_at = strftime"), false);
    assert.equal(note.includes("occurred_at = strftime"), false);
  });

  it("allows one item_expired and one item_delivered row per item", () => {
    const db = upgraded();
    const at = "2026-10-20T00:00:00.000Z";
    const digest = "ab".repeat(32);
    const expired = db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_expired', 'system', ?, ?)",
    );
    assert.equal(expired.run(AUDIT_ITEM, at).changes, 1);
    throwsMatching(() => expired.run(AUDIT_ITEM, at), /item_audit_one_expiry/);
    const delivered = db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, envelope_sha256, occurred_at) VALUES ('item_delivered', 'dot', ?, ?, ?)",
    );
    assert.equal(delivered.run(AUDIT_ITEM, digest, at).changes, 1);
    throwsMatching(() => delivered.run(AUDIT_ITEM, digest, at), /item_audit_one_delivery/);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE item_id = ? AND event = 'item_expired'").get(AUDIT_ITEM)?.n, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE item_id = ? AND event = 'item_delivered'").get(AUDIT_ITEM)?.n, 1);
    const other = "item_01234567-89ab-4cde-8fab-0123456789ac";
    assert.equal(expired.run(other, at).changes, 1);
    assert.equal(delivered.run(other, digest, at).changes, 1);
  });

  it("rejects a second head row, a non-advancing update, an unknown seq, and a delete", () => {
    const db = upgraded();
    const insert = db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_opened', 'dot', ?, ?)",
    );
    assert.equal(insert.run(AUDIT_ITEM, "2026-10-01T00:00:00.000Z").changes, 1);
    assert.equal(insert.run(AUDIT_ITEM, "2026-10-02T00:00:00.000Z").changes, 1);
    assert.deepEqual(fields(db.prepare("SELECT id, seq FROM item_audit_head").get()), { id: 1, seq: 2 });

    throwsMatching(() => db.exec("INSERT INTO item_audit_head (id, seq) VALUES (1, 3)"), /item_audit_append_only/);
    throwsMatching(() => db.exec("UPDATE item_audit_head SET seq = 1 WHERE id = 1"), /item_audit_append_only/);
    throwsMatching(() => db.exec("UPDATE item_audit_head SET seq = 2 WHERE id = 1"), /item_audit_append_only/);
    throwsMatching(() => db.exec("UPDATE item_audit_head SET seq = 9 WHERE id = 1"), /item_audit_append_only/);
    throwsMatching(() => db.exec("DELETE FROM item_audit_head"), /item_audit_append_only/);
    assert.deepEqual(fields(db.prepare("SELECT id, seq FROM item_audit_head").get()), { id: 1, seq: 2 });
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit_head").get()?.n, 1);
  });

  it("advances past a pruned max seq when the insert omits seq", () => {
    const db = upgraded();
    const insert = db.prepare(
      "INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_opened', 'dot', ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?))",
    );
    const kept = Number(insert.run(AUDIT_ITEM, "-92 days").lastInsertRowid);
    const max = Number(insert.run(AUDIT_ITEM, "-91 days").lastInsertRowid);
    assert.equal(kept, 1);
    assert.equal(max, 2);
    const headBefore = Number(db.prepare("SELECT seq FROM item_audit_head WHERE id = 1").get()?.seq);
    assert.equal(headBefore, max);
    const removed = db.prepare("DELETE FROM item_audit WHERE seq = ?").run(max);
    assert.equal(removed.changes, 1);
    assert.equal(Number(db.prepare("SELECT seq FROM item_audit_head WHERE id = 1").get()?.seq), headBefore);
    const next = Number(insert.run(AUDIT_ITEM, "-91 days").lastInsertRowid);
    assert.ok(next > headBefore);
    assert.equal(next, max + 1);
    assert.equal(Number(db.prepare("SELECT seq FROM item_audit_head WHERE id = 1").get()?.seq), next);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE seq = ?").get(kept)?.n, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE seq = ?").get(max)?.n, 0);
  });

  it("stops a second apply before the rebuild and keeps envelopes already set", () => {
    const db = new DatabaseSync(":memory:");
    applyPrior(db);
    insertItems(db);
    const statements = migrationStatements();
    assert.match(statements[0] ?? "", /migration_0006_already_applied/);
    const renameAt = statementIndex(statements, "ALTER TABLE item_authority RENAME TO item");
    const immutableAt = statementIndex(statements, "CREATE TRIGGER item_envelope_immutable");
    assert.ok(immutableAt > renameAt);
    for (const statement of statements.slice(0, renameAt + 1)) db.exec(statement);

    const envelope = "{\"kept\":true}";
    const digest = "cd".repeat(32);
    const written = db.prepare("UPDATE item SET envelope_json = ?, envelope_sha256 = ?").run(envelope, digest);
    assert.equal(written.changes, SEEDED.length);
    db.exec(statements[immutableAt] ?? "");

    const columns = `${OLD_COLUMNS.join(", ")}, envelope_json, envelope_sha256`;
    const before = db.prepare(`SELECT ${columns} FROM item ORDER BY id`).all();
    assert.equal(before.length, SEEDED.length);
    assert.ok(before.every((row) => row.envelope_json === envelope && row.envelope_sha256 === digest));
    throwsMatching(() => execFile(db, MIGRATION), /malformed JSON/);
    assert.deepEqual(db.prepare(`SELECT ${columns} FROM item ORDER BY id`).all(), before);
    assert.equal(db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'item_audit'").get()?.n, 0);
  });

  it("applies 0001 through 0006 on local D1", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "d1-0006-"));
    try {
      const config = join(dir, "wrangler.jsonc");
      const persist = join(dir, "state");
      writeFileSync(config, `${JSON.stringify({
        name: "admrn-bridge-migration-probe",
        compatibility_date: "2026-10-18",
        d1_databases: [{
          binding: "DB",
          database_name: "admrn-bridge",
          database_id: "00000000-0000-4000-8000-000000000000",
          migrations_dir: MIGRATIONS,
        }],
      }, null, 2)}\n`);
      const applied = wrangler([
        "d1", "migrations", "apply", "admrn-bridge",
        "--local",
        "--persist-to", persist,
        "--config", config,
      ], dir);
      assert.equal(applied.status, 0, applied.stdout + applied.stderr);
      assert.match(applied.stdout, /Executing on local database/);
      assert.doesNotMatch(applied.stdout + applied.stderr, /Executing on remote database/);

      const schema = localRows(config, persist, "SELECT sql FROM sqlite_master WHERE name = 'item_audit'");
      const sql = String(schema[0]?.sql);
      assert.match(sql, /length\(occurred_at\) = 24/);
      assert.match(sql, /occurred_at IS strftime\('%Y-%m-%dT%H:%M:%fZ', occurred_at\)/);
      assert.match(sql, /substr\(occurred_at, 12, 2\) < '24'/);
      assert.match(sql, /occurred_at >= '2020-01-01T00:00:00\.000Z'/);
      assert.equal(sql.includes("occurred_at = strftime"), false);
      assert.match(sql, /NOT GLOB '\*\[\^0-9a-f-\]\*'/);
      assert.equal(sql.includes("item_[0-9a-f][0-9a-f]"), false);

      const at = "2026-10-26T03:05:00.123Z";
      const validIds = [
        "item_01234567-89ab-4cde-8fab-0123456789ab",
        "item_01234567-89ab-4cde-bfab-0123456789ab",
      ];
      const malformedIds = [
        "item_-1234567-89ab-4cde-8fab-0123456789ab",
        "item_01234567-89AB-4cde-8fab-0123456789ab",
        "item_01234567-89ab-5cde-8fab-0123456789ab",
        "item_01234567-89ab-4cde-cfab-0123456789ab",
      ];
      const insertId = (itemId: string) => wrangler([
        "d1", "execute", "admrn-bridge",
        "--local",
        "--persist-to", persist,
        "--config", config,
        "--command", `INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_opened', 'dot', '${itemId}', '${at}')`,
        "--json",
      ], dir);
      for (const itemId of validIds) {
        const result = insertId(itemId);
        t.diagnostic(`${itemId} status ${String(result.status)} ${result.stdout.trim()}`);
        assert.equal(result.status, 0, `${itemId}\n${result.stdout}${result.stderr}`);
      }
      for (const itemId of malformedIds) {
        const result = insertId(itemId);
        t.diagnostic(`${itemId} status ${String(result.status)} ${(result.stdout + result.stderr).trim()}`);
        assert.notEqual(result.status, 0, itemId);
        assert.match(result.stdout + result.stderr, /CHECK constraint failed/, itemId);
      }
      const rows = localRows(config, persist, "SELECT item_id FROM item_audit ORDER BY item_id");
      assert.deepEqual(rows.map((row) => row.item_id), [...validIds].sort());

      const occurredItem = "item_01234567-89ab-4cde-8fab-0123456789ad";
      const acceptedAt = [new Date().toISOString(), "2026-10-28T23:59:59.999Z", "9999-12-31T23:59:59.999Z"];
      const rejectedAt = [
        "0000-00-00T00:00:00.000Z",
        "2026-13-01T00:00:00.000Z",
        "2026-10-26T00:00:60.000Z",
        "2026-02-30T00:00:00.000Z",
        "2026-10-01T24:30:00.000Z",
        "2026-10-28T24:00:00.000Z",
        "2019-12-31T23:59:59.999Z",
      ];
      const insertAt = (at: string) => wrangler([
        "d1", "execute", "admrn-bridge",
        "--local",
        "--persist-to", persist,
        "--config", config,
        "--command", `INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_opened', 'dot', '${occurredItem}', '${at}')`,
        "--json",
      ], dir);
      for (const at of acceptedAt) {
        const result = insertAt(at);
        t.diagnostic(`occurred_at ${at} status ${String(result.status)} ${(result.stdout + result.stderr).trim()}`);
        assert.equal(result.status, 0, `${at}\n${result.stdout}${result.stderr}`);
      }
      for (const at of rejectedAt) {
        const result = insertAt(at);
        t.diagnostic(`occurred_at ${at} status ${String(result.status)} ${(result.stdout + result.stderr).trim()}`);
        assert.notEqual(result.status, 0, at);
        assert.match(result.stdout + result.stderr, /CHECK constraint failed/, at);
      }
      const storedAt = localRows(
        config,
        persist,
        `SELECT occurred_at FROM item_audit WHERE item_id = '${occurredItem}' ORDER BY occurred_at`,
      );
      assert.deepEqual(storedAt.map((row) => row.occurred_at), [...acceptedAt].sort());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
