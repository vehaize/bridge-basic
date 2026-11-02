/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 * Schema regression tests use disposable :memory: databases only.
 */
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { describe, it } from "node:test";
import { fileURLToPath, URL } from "node:url";
import { sqlStatements } from "./sql-statements.mjs";

const DIRECTORY = fileURLToPath(new URL("../migrations/", import.meta.url));
const NAME = "0007_claude_basic_participant.sql";
const SQL = readFileSync(new URL(`../migrations/${NAME}`, import.meta.url), "utf8");
const ITEM = "item_01234567-89ab-4cde-8fab-0123456789ab";
const AT = "2026-10-27T00:00:00.000Z";
const HASH = "a".repeat(64);
const TABLES = ["owner_lock", "bootstrap_secret_spend", "participant_credential", "connect_code", "item", "item_audit", "item_audit_head"] as const;
const REHEARSAL = readFileSync(new URL("../docs/migration-0007-rehearsal.md", import.meta.url), "utf8");

// Execute the runbook's exact synthetic seed and read-only acceptance queries.
// The tracker is a local simulation of Wrangler bookkeeping, not a D1 runner.
function rehearsalSql(label: string): string {
  const blocks = [...REHEARSAL.matchAll(/```sql\r?\n-- rehearsal: ([\w-]+)\r?\n([\s\S]*?)\r?\n```/g)]
    .filter((match) => match[1] === label);
  assert.equal(blocks.length, 1, `expected one runbook SQL block: ${label}`);
  return blocks[0]![2]!;
}

function trackedPrior(): DatabaseSync {
  const db = prior();
  db.exec(`CREATE TABLE d1_migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
  )`);
  for (const name of readdirSync(DIRECTORY).filter((name) => name.endsWith(".sql") && name < NAME).sort()) {
    db.prepare("INSERT INTO d1_migrations (name) VALUES (?)").run(name);
  }
  return db;
}

function recordMigration(db: DatabaseSync): void {
  db.exec("BEGIN");
  try {
    db.exec(SQL);
    db.prepare("INSERT INTO d1_migrations (name) VALUES (?)").run(NAME);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function runbookChecks(db: DatabaseSync, label: string) {
  return sqlStatements(rehearsalSql(label)).flatMap((sql) => {
    assert.match(sql, /^\s*(?:WITH|SELECT)\b/i, `${label} must be a read-only query`);
    return db.prepare(sql).all();
  });
}

function checkRunbook(db: DatabaseSync, label: string): void {
  const checks = runbookChecks(db, label);
  assert.ok(checks.length > 0, `${label} must return acceptance checks`);
  for (const check of checks) assert.equal(check.result, "PASS", `${label}: ${String(check.check_name)}`);
}

function snapshots(db: DatabaseSync) {
  return rehearsalSql("snapshots").split(";").filter((sql) => sql.trim())
    .map((sql) => db.prepare(sql).all());
}

function indexKeys(db: DatabaseSync, table: string) {
  return db.prepare("SELECT name, \"unique\", origin, partial FROM pragma_index_list(?)").all(table)
    .map((row) => ({
      unique: row.unique, origin: row.origin, partial: row.partial,
      columns: db.prepare("SELECT name FROM pragma_index_info(?) ORDER BY seqno").all(String(row.name)),
    })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

function inspections(db: DatabaseSync) {
  return rehearsalSql("inspect").split(";").filter((sql) => sql.trim())
    .map((sql) => db.prepare(sql).all());
}

function guardDefinitions(db: DatabaseSync) {
  return db.prepare(`SELECT type, name, tbl_name, sql FROM sqlite_schema
    WHERE type IN ('index', 'trigger') AND name NOT GLOB 'sqlite_*'
    ORDER BY type, name`).all().map((row) => ({
      ...row, sql: String(row.sql).replace(/"/g, "").replace(/\s+/g, " ").trim(),
    }));
}

function prior(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  for (const name of readdirSync(DIRECTORY).filter((name) => name.endsWith(".sql") && name < NAME).sort()) {
    db.exec(readFileSync(new URL(`../migrations/${name}`, import.meta.url), "utf8"));
  }
  return db;
}
function rows(db: DatabaseSync, table: typeof TABLES[number] | "participant") {
  return db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all();
}
function seed(db: DatabaseSync): void {
  db.prepare("INSERT INTO owner_lock VALUES (1, 'synthetic-owner@example.invalid', ?, 'first-boot')").run(AT);
  db.prepare("INSERT INTO bootstrap_secret_spend VALUES ('synthetic-bootstrap-hash', ?)").run(AT);
  db.exec("UPDATE participant SET enabled = 0 WHERE id = 'dot'");
  db.exec("UPDATE participant SET wake_url = 'https://receiver.example/hook' WHERE id = 'grok_bot'");
  db.prepare("INSERT INTO participant_credential VALUES ('synthetic-bearer', 'grok_bot', 'bearer', ?, NULL, ?, ?, NULL)").run("b".repeat(64), AT, AT);
  db.prepare("INSERT INTO participant_credential VALUES ('synthetic-dot', 'dot', 'oauth_grant', NULL, ?, ?, ?, NULL)").run(HASH, AT, AT);
  db.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, '2099-01-01T00:00:00.000Z', ?)").run(HASH, AT, "synthetic-spent");
  db.prepare(`INSERT INTO item (id, sender, recipient, kind, title, body, state, deadline_at,
    result, sources, review_note, checked, idempotency_key, request_sha256, created_at,
    claimed_at, submitted_at, reviewed_at, updated_at, delivered_at, envelope_json, envelope_sha256)
    VALUES (?, 'dot', 'grok_bot', 'task', 'Synthetic', 'Local', 'accepted', '2099-01-01T00:00:00.000Z',
    'Result', '[]', 'Checked', 1, 'req_preserved_001', ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(ITEM, HASH, AT, AT, AT, AT, AT, AT, '{"synthetic":"unchanged bytes"}', HASH);
  db.prepare("INSERT INTO item_audit (event, actor, item_id, envelope_sha256, occurred_at) VALUES ('item_delivered', 'grok_bot', ?, ?, ?)").run(ITEM, HASH, AT);
}
function objects(db: DatabaseSync) {
  return db.prepare("SELECT type, name FROM sqlite_schema WHERE type IN ('trigger', 'index') AND name NOT LIKE 'sqlite_%' ORDER BY type, name").all();
}

describe("Claude Basic schema preservation", () => {
  it("runs seven separate documented count queries without a compound SELECT", () => {
    const queries = sqlStatements(rehearsalSql("counts"));
    assert.equal(queries.length, TABLES.length);
    const db = trackedPrior();
    try {
      db.exec(rehearsalSql("seed"));
      for (const [index, query] of queries.entries()) {
        assert.doesNotMatch(query, /\bUNION\b/i);
        assert.equal([...query.matchAll(/count\(\*\)/gi)].length, 1);
        const result = db.prepare(query).all();
        assert.equal(result.length, 1);
        assert.equal(result[0]?.check_name, TABLES[index]);
        assert.equal(result[0]?.actual, result[0]?.expected);
        assert.equal(result[0]?.result, "PASS");
      }
    } finally { db.close(); }
  });

  it("preserves all existing data, indexes, triggers and foreign keys while adding Claude", () => {
    const db = prior();
    try {
      seed(db);
      const before = TABLES.map((table) => rows(db, table));
      const participants = rows(db, "participant");
      const guards = objects(db);
      db.exec(SQL);
      assert.deepEqual(TABLES.map((table) => rows(db, table)), before);
      assert.deepEqual(rows(db, "participant").filter((row) => row.id !== "claude"), participants);
      assert.deepEqual({ ...db.prepare("SELECT * FROM participant WHERE id = 'claude'").get() }, { id: "claude", enabled: 1, wake_url: null });
      assert.deepEqual(objects(db), guards);
      assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
      assert.equal(db.prepare("PRAGMA foreign_key_list(participant_credential)").get()?.table, "participant");
      assert.match(String(db.prepare("SELECT sql FROM sqlite_schema WHERE name = 'item'").get()?.sql), /WITHOUT ROWID/);
      assert.throws(() => db.exec("UPDATE item SET envelope_json = '{}'"), /item_envelope_immutable/);
      assert.throws(() => db.exec("UPDATE item_audit SET actor = 'claude'"), /item_audit_append_only/);
      assert.throws(() => db.exec("UPDATE item_audit_head SET seq = 0"), /item_audit_append_only/);
      assert.throws(() => db.exec("INSERT OR REPLACE INTO item SELECT * FROM item"), /item_envelope_immutable/);
      assert.throws(() => db.prepare("INSERT INTO item_audit (event, actor, item_id, envelope_sha256, occurred_at) VALUES ('item_delivered', 'claude', ?, ?, ?)").run(ITEM, HASH, AT), /item_audit_one_delivery/);
      assert.throws(() => db.exec("UPDATE participant SET wake_url = 'https://receiver.example/hook' WHERE id = 'claude'"), /CHECK constraint failed/);
      assert.throws(() => db.exec("INSERT INTO participant (id) VALUES ('unknown')"), /CHECK constraint failed/);
    } finally { db.close(); }
  });

  it("preserves the audit high-water mark after retention removes every event", () => {
    const db = prior();
    try {
      for (let index = 0; index < 3; index += 1) {
        db.prepare("INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_opened', 'dot', ?, '2020-01-01T00:00:00.000Z')").run(ITEM);
      }
      db.exec("DELETE FROM item_audit");
      assert.equal(db.prepare("SELECT seq FROM item_audit_head").get()?.seq, 3);
      assert.equal(db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'item_audit'").get()?.seq, 3);
      db.exec(SQL);
      assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit").get()?.n, 0);
      assert.equal(db.prepare("SELECT seq FROM item_audit_head").get()?.seq, 3);
      assert.equal(db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'item_audit'").get()?.seq, 3);
      checkRunbook(db, "residue");
      db.prepare("INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES ('item_opened', 'claude', ?, ?)").run(ITEM, AT);
      assert.equal(db.prepare("SELECT seq FROM item_audit").get()?.seq, 4);
      assert.equal(db.prepare("SELECT seq FROM item_audit_head").get()?.seq, 4);
      assert.equal(db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'item_audit'").get()?.seq, 4);
    } finally { db.close(); }
  });

  it("allows Claude OAuth rows but rejects bearer credentials, duplicate live grants and self routing", () => {
    const db = prior();
    try {
      db.exec(SQL);
      db.prepare("INSERT INTO participant_credential (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at) VALUES ('synthetic-claude', 'claude', 'oauth_grant', ?, ?, ?)").run(HASH, AT, AT);
      assert.throws(() => db.prepare("INSERT INTO participant_credential (id, participant, kind, token_sha256, owner_claimed_at, created_at) VALUES ('synthetic-bad', 'claude', 'bearer', ?, ?, ?)").run("b".repeat(64), AT, AT), /CHECK constraint failed/);
      assert.throws(() => db.prepare("INSERT INTO participant_credential (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at) VALUES ('synthetic-duplicate', 'claude', 'oauth_grant', ?, ?, ?)").run("c".repeat(64), AT, AT), /UNIQUE constraint failed/);
      db.prepare("INSERT INTO connect_code VALUES (?, 'claude', ?, '2099-01-01T00:00:00.000Z', NULL)").run(HASH, AT);
      const insert = db.prepare("INSERT INTO item (id, sender, recipient, kind, title, body, state, deadline_at, idempotency_key, request_sha256, created_at, updated_at) VALUES (?, 'claude', ?, 'question', 'Synthetic', 'Local', 'open', '2099-01-01T00:00:00.000Z', 'req_claude_001', ?, ?, ?)");
      assert.throws(() => insert.run(ITEM, "claude", HASH, AT, AT), /CHECK constraint failed/);
      insert.run(ITEM, "dot", HASH, AT, AT);
    } finally { db.close(); }
  });

  it("refuses a second execution before changing stored rows", () => {
    const db = prior();
    try {
      seed(db); db.exec(SQL);
      const before = TABLES.map((table) => rows(db, table));
      const guards = objects(db);
      assert.throws(() => db.exec(SQL), /malformed JSON/);
      assert.deepEqual(TABLES.map((table) => rows(db, table)), before);
      assert.deepEqual(objects(db), guards);
      assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
    } finally { db.close(); }
  });

  it("passes the exact seeded C-04 read-only checks, preserving bytes and allocating above a deleted audit tail", () => {
    const db = trackedPrior();
    try {
      db.exec(rehearsalSql("seed"));
      for (const label of ["counts", "audit", "objects", "residue", "before"]) checkRunbook(db, label);
      const before = snapshots(db);
      const definitions = guardDefinitions(db);
      const indexedTables = ["item", "participant_credential", "participant", "connect_code"];
      const keys = indexedTables.map((table) => indexKeys(db, table));
      const foreignKeys = db.prepare("PRAGMA foreign_key_list(participant_credential)").all();
      assert.equal(foreignKeys.length, 1);
      assert.deepEqual({ ...foreignKeys[0] }, {
        id: 0, seq: 0, table: "participant", from: "participant", to: "id",
        on_update: "NO ACTION", on_delete: "NO ACTION", match: "NONE",
      });
      assert.equal(inspections(db).length, 11);
      recordMigration(db);
      for (const label of ["counts", "audit", "objects", "residue", "after"]) checkRunbook(db, label);
      const after = snapshots(db);
      assert.deepEqual(after.slice(0, TABLES.length), before.slice(0, TABLES.length));
      assert.deepEqual(after[7]!.filter((row) => row.id !== "claude"), before[7]);
      assert.deepEqual(after[8]!.filter((row) => row.name !== NAME), before[8]);
      assert.deepEqual(guardDefinitions(db), definitions);
      assert.deepEqual(indexedTables.map((table) => indexKeys(db, table)), keys);
      assert.deepEqual(db.prepare("PRAGMA foreign_key_list(participant_credential)").all(), foreignKeys);
      assert.deepEqual({ ...db.prepare("PRAGMA foreign_keys").get() }, { foreign_keys: 1 });
      assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
      assert.deepEqual({ ...db.prepare("PRAGMA quick_check").get() }, { quick_check: "ok" });
      assert.match(String(db.prepare("SELECT sql FROM sqlite_schema WHERE name = 'item'").get()?.sql), /WITHOUT ROWID/);
      assert.deepEqual(db.prepare("SELECT name, seq FROM sqlite_sequence ORDER BY name").all().map((row) => ({ ...row })), [
        { name: "d1_migrations", seq: 7 }, { name: "item_audit", seq: 5 },
      ]);
      assert.equal(inspections(db).length, 11);

      // Existing delivery/expiry facts remain unique after the rebuild.
      const append = db.prepare("INSERT INTO item_audit (event, actor, item_id, envelope_sha256, occurred_at) VALUES (?, ?, ?, ?, ?)");
      assert.throws(() => append.run("item_delivered", "claude", ITEM, HASH, AT), /item_audit_one_delivery/);
      assert.throws(() => append.run("item_expired", "system", "item_11234567-89ab-4cde-8fab-0123456789ab", null, AT), /item_audit_one_expiry/);
      assert.throws(() => db.exec("DELETE FROM item_audit_head"), /item_audit_append_only/);
      assert.throws(() => db.exec("UPDATE participant_credential SET participant = 'unknown' WHERE id = 'synthetic-dot'"), /FOREIGN KEY constraint failed/);
      assert.throws(() => db.exec(`INSERT INTO participant_credential
        SELECT 'synthetic-duplicate', participant, kind, NULL,
          '${"c".repeat(64)}', owner_claimed_at, created_at, NULL
        FROM participant_credential WHERE id = 'synthetic-dot'`), /UNIQUE constraint failed/);
      checkRunbook(db, "audit");
      db.exec(rehearsalSql("append"));
      checkRunbook(db, "appended");
      assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
      assert.deepEqual({ ...db.prepare("PRAGMA quick_check").get() }, { quick_check: "ok" });
    } finally { db.close(); }
  });

  for (const [name, mutation, gate] of [
    ["lost item row", `DELETE FROM item WHERE id = '${ITEM}'`, "counts"],
    ["reset audit AUTOINCREMENT", "UPDATE sqlite_sequence SET seq = 4 WHERE name = 'item_audit'", "audit"],
    ["missing trigger", "DROP TRIGGER item_audit_block_update", "objects"],
    ["missing index", "DROP INDEX participant_credential_one_active", "objects"],
    ["leftover rebuild table", "CREATE TABLE item_basic (id TEXT)", "residue"],
    ["leftover rebuild sequence", "INSERT INTO sqlite_sequence VALUES ('item_audit_basic', 5)", "residue"],
    ["unexpected roster state", "UPDATE participant SET enabled = 0 WHERE id = 'claude'", "after"],
    ["missing migration tracking", `DELETE FROM d1_migrations WHERE name = '${NAME}'`, "after"],
  ] as const) {
    it(`fails the documented gate for ${name}`, () => {
      const db = trackedPrior();
      try {
        db.exec(rehearsalSql("seed"));
        recordMigration(db);
        db.exec(mutation);
        assert.ok(runbookChecks(db, gate).some((row) => row.result === "FAIL"));
      } finally { db.close(); }
    });
  }
});
