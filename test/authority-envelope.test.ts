/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, it, mock } from "node:test";
import { fileURLToPath } from "node:url";
import { buildEnvelope, checkStoredEnvelope, isCanonicalSource } from "../src/authority-envelope.ts";
import { ItemLifecycle, LifecycleError, pruneAuditRows, sweepExpiredItems } from "../src/item-lifecycle.ts";
import { ITEM_DEADLINE_DEFAULT_MINUTES } from "../src/provisional.ts";
import { pinSqliteNow, SqliteD1 } from "./d1-sqlite.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

type ItemRow = {
  id: string;
  sender: string;
  idempotency_key: string;
  title: string;
  state: string;
};

const ORIGINAL: ItemRow[] = [
  { id: "other-id", sender: "dot", idempotency_key: "other-key", title: "other-envelope", state: "claimed" },
  { id: "owner-id", sender: "dot", idempotency_key: "existing-key", title: "owner-envelope", state: "open" },
];

function note(): string {
  return readFileSync(join(ROOT, "docs/design/authority-envelope.md"), "utf8");
}

function sketch(): string {
  const match = /```sql\r?\n(CREATE TABLE item_authority[\s\S]*?)```/.exec(note());
  assert.ok(match, "authority envelope sketch missing");
  return match[1];
}

function sqlBlocks(): string[] {
  return [...note().matchAll(/```sql\r?\n([\s\S]*?)```/g)].map((match) => match[1]);
}

function statementsContaining(fragment: string): string[] {
  const block = sqlBlocks().find((sql) => sql.includes(fragment));
  assert.ok(block, fragment);
  return block.split(/;\r?\n/).map((part) => part.trim()).filter((part) => part.length > 0).map((part) => (
    part.endsWith(";") ? part : `${part};`
  ));
}

function digest(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

function pinnedEnvelope(): string {
  const match = /```json\r?\n(\{.*\})\r?\n```/.exec(note());
  assert.ok(match, "pinned envelope missing");
  return match[1];
}

function applySketch(db: DatabaseSync): void {
  db.exec("PRAGMA recursive_triggers=OFF");
  db.exec(readFileSync(join(ROOT, "migrations/0002_item_lifecycle.sql"), "utf8"));
  db.exec(readFileSync(join(ROOT, "migrations/0005_item_receipt.sql"), "utf8"));
  db.exec(sketch());
}

function database(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  applySketch(db);
  const insert = db.prepare(`INSERT INTO item (
    id, sender, recipient, kind, title, body, state, deadline_at,
    idempotency_key, request_sha256, created_at, updated_at
  ) VALUES (?, ?, 'grok_bot', 'task', ?, 'body', ?, '2026-10-25T12:00:00.000Z', ?, ?, '2026-10-25T11:00:00.000Z', '2026-10-25T11:00:00.000Z')`);
  for (const row of ORIGINAL) {
    insert.run(row.id, row.sender, row.title, row.state, row.idempotency_key, "a".repeat(64));
  }
  return db;
}

function stored(db: DatabaseSync): ItemRow[] {
  return db.prepare("SELECT id, sender, idempotency_key, title, state FROM item ORDER BY id").all().map((row) => ({
    id: String(row.id),
    sender: String(row.sender),
    idempotency_key: String(row.idempotency_key),
    title: String(row.title),
    state: String(row.state),
  }));
}

function aborts(db: DatabaseSync, sql: string): void {
  assert.throws(() => db.exec(sql), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.match(error.message, /item_envelope_immutable/);
    return true;
  });
  assert.deepEqual(stored(db), ORIGINAL);
}

function rejectsRowid(db: DatabaseSync, sql: string): void {
  assert.throws(() => db.exec(sql), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.match(error.message, /no such column|no column named/);
    return true;
  });
  assert.deepEqual(stored(db), ORIGINAL);
}

describe("item unique-key replace guard", () => {
  it("INSERT OR REPLACE with a fresh id and a reused (sender, idempotency_key) aborts", () => {
    const db = database();
    aborts(db, `INSERT OR REPLACE INTO item (
      id, sender, recipient, kind, title, body, state, deadline_at,
      idempotency_key, request_sha256, created_at, updated_at
    ) VALUES (
      'fresh-id', 'dot', 'grok_bot', 'task', 'replaced-envelope', 'body', 'open',
      '2026-10-25T12:00:00.000Z', 'existing-key', '${"b".repeat(64)}',
      '2026-10-25T11:00:00.000Z', '2026-10-25T11:00:00.000Z'
    )`);
  });

  it("UPDATE OR REPLACE of idempotency_key onto another item aborts", () => {
    const db = database();
    aborts(db, "UPDATE OR REPLACE item SET idempotency_key = 'existing-key' WHERE id = 'other-id'");
  });

  it("UPDATE OR REPLACE of id onto another item aborts", () => {
    const db = database();
    aborts(db, "UPDATE OR REPLACE item SET id = 'owner-id' WHERE id = 'other-id'");
  });

  it("UPDATE OR REPLACE of sender onto another item's key aborts", () => {
    const db = database();
    db.exec("UPDATE item SET sender = 'grok_bot', recipient = 'dot', idempotency_key = 'existing-key' WHERE id = 'other-id'");
    const before = stored(db);
    assert.throws(() => db.exec("UPDATE OR REPLACE item SET sender = 'dot', recipient = 'grok_bot' WHERE id = 'other-id'"), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /item_envelope_immutable/);
      return true;
    });
    assert.deepEqual(stored(db), before);
  });

  it("INSERT OR REPLACE with an explicit rowid of an existing row aborts", () => {
    const db = database();
    rejectsRowid(db, `INSERT OR REPLACE INTO item (
      rowid, id, sender, recipient, kind, title, body, state, deadline_at,
      idempotency_key, request_sha256, created_at, updated_at
    ) VALUES (
      (SELECT rowid FROM item WHERE id = 'owner-id'), 'fresh-id', 'dot', 'grok_bot', 'task', 'replaced-envelope', 'body', 'open',
      '2026-10-25T12:00:00.000Z', 'fresh-key', '${"b".repeat(64)}',
      '2026-10-25T11:00:00.000Z', '2026-10-25T11:00:00.000Z'
    )`);
  });

  it("UPDATE OR REPLACE SET rowid of another row aborts", () => {
    const db = database();
    rejectsRowid(db, "UPDATE OR REPLACE item SET rowid = (SELECT rowid FROM item WHERE id = 'owner-id') WHERE id = 'other-id'");
  });

  for (const column of ["oid", "_rowid_"]) {
    it(`INSERT OR REPLACE with an explicit ${column} of an existing row aborts`, () => {
      const db = database();
      rejectsRowid(db, `INSERT OR REPLACE INTO item (
        ${column}, id, sender, recipient, kind, title, body, state, deadline_at,
        idempotency_key, request_sha256, created_at, updated_at
      ) VALUES (
        (SELECT rowid FROM item WHERE id = 'owner-id'), 'fresh-id', 'dot', 'grok_bot', 'task', 'replaced-envelope', 'body', 'open',
        '2026-10-25T12:00:00.000Z', 'fresh-key', '${"b".repeat(64)}',
        '2026-10-25T11:00:00.000Z', '2026-10-25T11:00:00.000Z'
      )`);
    });

    it(`UPDATE OR REPLACE SET ${column} of another row aborts`, () => {
      const db = database();
      rejectsRowid(db, `UPDATE OR REPLACE item SET ${column} = (SELECT rowid FROM item WHERE id = 'owner-id') WHERE id = 'other-id'`);
    });
  }

  it("a lifecycle state update commits", () => {
    const db = database();
    db.exec("UPDATE item SET state = 'submitted', updated_at = created_at WHERE id = 'other-id'");
    assert.deepEqual(stored(db), [
      { ...ORIGINAL[0], state: "submitted" },
      ORIGINAL[1],
    ]);
  });
});

const AUDIT_ITEM = "item_01234567-89ab-4cde-8fab-0123456789ab";

function insertEnvelope(db: DatabaseSync, id: string, key: string, state: string, envelope: string): void {
  db.prepare(`INSERT INTO item (
    id, sender, recipient, kind, title, body, state, deadline_at,
    idempotency_key, request_sha256, created_at, updated_at,
    envelope_json, envelope_sha256
  ) VALUES (
    ?, 'dot', 'grok_bot', 'task', 't', 'body', ?, '2099-01-01T00:00:00.000Z',
    ?, ?, '2026-10-25T11:00:00.000Z', '2026-10-25T11:00:00.000Z', ?, ?
  )`).run(id, state, key, "c".repeat(64), envelope, digest(envelope));
}

function itemState(db: DatabaseSync, id: string): string {
  const row = db.prepare("SELECT state FROM item WHERE id = ?").get(id);
  assert.ok(row);
  return String(row.state);
}

describe("invalid stored envelope", () => {
  const now = "2026-10-26T00:00:00.000Z";
  const valid = pinnedEnvelope();
  const invalid = "{";

  it("cancel denies an invalid stored envelope", () => {
    const db = new DatabaseSync(":memory:");
    applySketch(db);
    insertEnvelope(db, "valid-id", "valid-key", "open", valid);
    insertEnvelope(db, "invalid-id", "invalid-key", "open", invalid);
    const sql = statementsContaining("json_valid(envelope_json)").find((statement) => statement.includes("state = 'cancelled'"));
    assert.ok(sql);
    const denied = db.prepare(sql).run("invalid-id", "dot", now, digest(invalid));
    assert.equal(denied.changes, 0);
    assert.equal(itemState(db, "invalid-id"), "open");
    const admitted = db.prepare(sql).run("valid-id", "dot", now, digest(valid));
    assert.equal(admitted.changes, 1);
    assert.equal(itemState(db, "valid-id"), "cancelled");
  });

  it("review denies an invalid stored envelope", () => {
    const db = new DatabaseSync(":memory:");
    applySketch(db);
    insertEnvelope(db, "valid-id", "valid-key", "submitted", valid);
    insertEnvelope(db, "invalid-id", "invalid-key", "submitted", invalid);
    const sql = statementsContaining("json_valid(envelope_json)").find((statement) => statement.includes("state = 'submitted'"));
    assert.ok(sql);
    const denied = db.prepare(sql).run("invalid-id", "dot", "accepted", 0, null, now, digest(invalid));
    assert.equal(denied.changes, 0);
    assert.equal(itemState(db, "invalid-id"), "submitted");
    const admitted = db.prepare(sql).run("valid-id", "dot", "accepted", 0, null, now, digest(valid));
    assert.equal(admitted.changes, 1);
    assert.equal(itemState(db, "valid-id"), "accepted");
  });
});

describe("retention horizons", () => {
  it("keeps audit rows for 90 days and items for 30 days", () => {
    const db = new DatabaseSync(":memory:");
    applySketch(db);
    const insertAudit = db.prepare(`INSERT INTO item_audit (event, actor, item_id, occurred_at)
      VALUES ('item_cancelled', 'dot', ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?))`);
    const youngAudit = Number(insertAudit.run(AUDIT_ITEM, "-89 days").lastInsertRowid);
    const oldAudit = Number(insertAudit.run(AUDIT_ITEM, "-91 days").lastInsertRowid);
    const insertItem = db.prepare(`INSERT INTO item (
      id, sender, recipient, kind, title, body, state, deadline_at,
      idempotency_key, request_sha256, created_at, updated_at
    ) VALUES (
      ?, 'dot', 'grok_bot', 'task', 't', 'body', 'cancelled', '2099-01-01T00:00:00.000Z',
      ?, ?, '2026-10-25T11:00:00.000Z', strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
    )`);
    insertItem.run("young-item", "young-key", "d".repeat(64), "-29 days");
    insertItem.run("old-item", "old-key", "e".repeat(64), "-31 days");

    assert.throws(() => db.prepare("DELETE FROM item_audit WHERE seq = ?").run(youngAudit), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /item_audit_append_only/);
      return true;
    });
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE seq = ?").get(youngAudit)?.n, 1);

    const [auditPrune, itemPurge] = statementsContaining("DELETE FROM item_audit");
    assert.match(auditPrune, /DELETE FROM item_audit/);
    assert.match(auditPrune, /-90 days/);
    assert.match(itemPurge, /DELETE FROM item\b/);
    assert.match(itemPurge, /-30 days/);
    db.exec(auditPrune);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE seq = ?").get(youngAudit)?.n, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item_audit WHERE seq = ?").get(oldAudit)?.n, 0);
    db.exec(itemPurge);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item WHERE id = 'young-item'").get()?.n, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM item WHERE id = 'old-item'").get()?.n, 0);
    assert.equal(note().includes("Deletes older than 30 days"), false);
    assert.equal(
      note().includes("Deletes of audit rows older than 90 days are a separate batch and are not part of an item write. Items stay at 30 days."),
      true,
    );
  });
});

const AUTHORITY_FLAGS = [
  "additional_tools",
  "credential_creation",
  "credentials",
  "delegation",
  "external_actions",
  "message_grants_authority",
  "private_resources",
  "resource_labels_grant_access",
  "spending",
] as const;

const HIDDEN = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200b\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}\ud800-\udfff]/u;
const TOKEN = /admrn_gb_[A-Za-z0-9_-]{43}/;
const DNS = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z](?:[a-z0-9-]*[a-z0-9])?$/;
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

type Flag = (typeof AUTHORITY_FLAGS)[number];

type StoredEnvelope = {
  json: string;
  authority: Record<Flag, false>;
  allowedSources: readonly string[];
};

function canonicalSource(value: string): string | undefined {
  if ([...value].length < 1 || [...value].length > 300) return undefined;
  if (!value.trim() || HIDDEN.test(value) || TOKEN.test(value)) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.href !== value || url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.port !== "") return undefined;
  const host = url.hostname;
  if (host !== host.toLowerCase() || !DNS.test(host) || host.split(".").some((label) => label.length > 63)) return undefined;
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".invalid")) return undefined;
  if (!percentCanonical(value) || !markHasBody(value, "?") || !markHasBody(value, "#")) return undefined;
  return value;
}

function percentCanonical(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    if (value[i] !== "%") continue;
    const hex = value.slice(i + 1, i + 3);
    if (!/^[0-9A-F]{2}$/.test(hex)) return false;
    if (UNRESERVED.test(String.fromCharCode(Number.parseInt(hex, 16)))) return false;
    i += 2;
  }
  return true;
}

function markHasBody(value: string, mark: "?" | "#"): boolean {
  const at = value.indexOf(mark);
  return at === -1 || at < value.length - 1;
}

function admitSources(values: readonly string[]): StoredEnvelope | "rejected" {
  if (values.length > 3) return "rejected";
  const accepted: string[] = [];
  for (const value of values) {
    const canonical = canonicalSource(value);
    if (canonical === undefined || accepted.includes(canonical)) return "rejected";
    accepted.push(canonical);
  }
  accepted.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  const authority: Record<Flag, false> = {
    additional_tools: false,
    credential_creation: false,
    credentials: false,
    delegation: false,
    external_actions: false,
    message_grants_authority: false,
    private_resources: false,
    resource_labels_grant_access: false,
    spending: false,
  };
  const allowedSources = accepted;
  const json = JSON.stringify({
    authority,
    contract_version: 1,
    limits: { max_answer_chars: 800, max_resources: 3, max_sources: 3 },
    scope: { allowed_resources: [], allowed_sources: allowedSources },
  });
  return { json, authority, allowedSources };
}

function citeAgainst(allowed: readonly string[], sources: readonly string[] | undefined): "ok" | "citation_mismatch" {
  const list = sources ?? [];
  for (const entry of list) {
    if (!allowed.includes(entry) || canonicalSource(entry) !== entry) return "citation_mismatch";
  }
  return "ok";
}

function storedEnvelope(values: readonly string[]): StoredEnvelope {
  const admitted = admitSources(values);
  if (admitted === "rejected") assert.fail("rejected");
  return admitted;
}

function bridgeSketch(): string {
  return [canonicalSource, percentCanonical, markHasBody, admitSources, citeAgainst].map((fn) => fn.toString()).join("\n");
}

const ADOPTED_ALLOWED_SOURCES =
  "Listing a URL constrains permitted citations; it does not grant network, credential, private-resource or external-action authority. A receiver may read it only under independently established read permissions and applicable safety checks, including redirects. All-false flags grant no additional authority.";

function sectionByHeading(heading: string): string {
  const marker = `${heading}\n`;
  const text = note();
  const start = text.indexOf(marker);
  assert.ok(start >= 0, heading);
  const rest = text.slice(start);
  const next = rest.indexOf("\n## ", marker.length);
  const end = next === -1 ? rest.length : next;
  assert.ok(end > marker.length, heading);
  return rest.slice(0, end);
}

function constraintSection(): string {
  return sectionByHeading("## Declared reference constraint");
}

function paragraphBefore(section: string, anchor: string): string {
  const end = section.indexOf(anchor);
  assert.ok(end > 0, anchor);
  const paragraphs = section.slice(0, end).trim().split(/\n\n+/);
  const paragraph = paragraphs[paragraphs.length - 1] ?? "";
  assert.ok(paragraph.length > 0, anchor);
  return paragraph;
}

function numberedItem(section: string, number: number): string {
  const start = section.search(new RegExp(`(?:^|\\n)${number}\\. `));
  assert.ok(start >= 0, `item ${number}`);
  const rest = section.slice(start).replace(/^\n/, "");
  const next = rest.search(/\n\d+\. /);
  return (next === -1 ? rest : rest.slice(0, next)).trim();
}

describe("allowed_sources declared reference constraint", () => {
  it("keeps the adopted allowed_sources wording", () => {
    const text = note();
    const kept = [
      "| `allowed_sources` | Zero to three sender-supplied `https` references. The grammar below is syntax only. It does not show that a host is public. The Worker does not fetch. Listing a URL constrains permitted citations. The list does not grant a read. A receiver may read it only under independently established read permissions. |",
      "the hostname is not on the non-public host list. That list is `localhost` and any name ending in `.localhost`, `.local`, `.internal`, or `.invalid`, and it is the only non-public host list in this note;",
      "A string that passes is still a reference the sender wrote. The bridge does not resolve DNS, and the Worker does not fetch. `allowed_sources` is not a verified public source. Listing a reference constrains permitted citations. The list does not grant a read. A receiver may read it only under independently established read permissions.",
    ];
    for (const sentence of kept) assert.equal(text.includes(sentence), true, sentence);
    const adoptedAt = [
      ["Declared reference constraint", constraintSection()],
      ["authority paragraph", paragraphBefore(sectionByHeading("## Authority flags"), "Owner approval stays")],
      ["Contract decisions item", numberedItem(sectionByHeading("## Contract decisions"), 6)],
    ] as const;
    for (const [place, section] of adoptedAt) assert.equal(section.includes(ADOPTED_ALLOWED_SOURCES), true, place);
    const emptyList = "An empty source list means a later result cites nothing.";
    assert.equal(text.split(emptyList).length - 1, 2);
  });

  it("states that egress is the receiver's duty and not the bridge boundary", () => {
    const section = constraintSection();
    const required = [
      "declared reference constraint, not network authority",
      "The Bridge stores the declared list and validates its shape. The Bridge does not fetch.",
      "A listed reference never authorizes using a credential, and it never authorizes reaching a private resource.",
      "Matching an entry is not proof that the source is public, and it is not proof that the content is correct.",
      ADOPTED_ALLOWED_SOURCES,
      "A rejected list is not stored, and nothing from it persists.",
      "An empty source list means a later result cites nothing.",
      "an empty list admits no citation",
      "That rejection is the hostname normalisation check.",
      "At its boundary the Bridge does not resolve DNS, does not inspect resolved addresses, does not open a connection, does not follow a redirect, and does not send a request.",
      "It therefore does not send a credential, a cookie, or an authorization header.",
      "A match against `allowed_sources` is not an egress decision.",
      "Egress enforcement is on that receiver.",
      "checks again on every connection",
      "private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)",
      "this network (`0.0.0.0/8`)",
      "loopback (`127.0.0.0/8`, `::1`)",
      "unspecified (`::/128`)",
      "link-local (`169.254.0.0/16`, `fe80::/10`)",
      "CGNAT (`100.64.0.0/10`)",
      "unique-local IPv6 (`fc00::/7`)",
      "metadata ranges (`169.254.169.254`, `fd00:ec2::254`)",
      "An IPv4-mapped address (`::ffff:0:0/96`) is blocked when its embedded IPv4 is on that IPv4 blocklist.",
      "A NAT64 address (`64:ff9b::/96`) is blocked when its embedded IPv4 is on that IPv4 blocklist.",
      "A 6to4 address (`2002::/16`) is blocked when the embedded IPv4 in bits 16-47 is on that IPv4 blocklist.",
      "re-validates each hop",
      "off the declared list",
      "The scheme is `https` only.",
      "The receiver sends no credential, cookie, or authorization header to a listed source.",
    ];
    for (const sentence of required) assert.equal(section.includes(sentence), true, sentence);
    assert.equal(/169\.254|100\.64|fc00::|fe80::|0\.0\.0\.0|::\/128|ffff:0:0|64:ff9b|2002::/.test(bridgeSketch()), false);
  });

  it("stores the canonical list and the pinned empty envelope", () => {
    const empty = storedEnvelope([]);
    assert.equal(empty.json, pinnedEnvelope());
    assert.deepEqual(empty.allowedSources, []);
    for (const flag of AUTHORITY_FLAGS) assert.equal(empty.authority[flag], false);

    const stored = storedEnvelope([
      "https://b.example/path",
      "https://a.example/",
      "https://sub.example.org/path?q=1#fragment",
    ]);
    assert.deepEqual(stored.allowedSources, [
      "https://a.example/",
      "https://b.example/path",
      "https://sub.example.org/path?q=1#fragment",
    ]);
    assert.equal(stored.json, JSON.stringify(JSON.parse(stored.json)));
    const parsed = JSON.parse(stored.json) as { scope: { allowed_sources: string[] }; authority: Record<string, boolean> };
    assert.deepEqual(parsed.scope.allowed_sources, stored.allowedSources);
    for (const flag of AUTHORITY_FLAGS) assert.equal(parsed.authority[flag], false);
    assert.equal(admitSources([
      "https://a.example/",
      "https://b.example/",
      "https://c.example/",
      "https://d.example/",
    ]), "rejected");
    assert.equal(admitSources(["https://a.example/", "https://a.example/"]), "rejected");
  });

  it("rejects a hostname the parser would rewrite and stores a lowercase host unchanged", () => {
    assert.equal(admitSources(["https://Example.com/"]), "rejected");
    assert.equal(admitSources(["https://exämple.com/"]), "rejected");
    assert.equal(admitSources(["https://example.net"]), "rejected");
    assert.equal(admitSources(["https://example.com:443/"]), "rejected");
    assert.equal(admitSources(["https://example.com./"]), "rejected");
    assert.equal(admitSources([`https://${"a".repeat(64)}.example/`]), "rejected");
    const stored = storedEnvelope([`https://${"a".repeat(63)}.example/PATH`]);
    assert.equal(stored.allowedSources[0], `https://${"a".repeat(63)}.example/PATH`);
    assert.equal(new URL(stored.allowedSources[0]).hostname, `${"a".repeat(63)}.example`);
    const punycode = storedEnvelope(["https://xn--exmple-cua.com/"]);
    assert.equal(punycode.allowedSources[0], "https://xn--exmple-cua.com/");
  });

  it("keeps an empty source list as cite-nothing", () => {
    const empty = storedEnvelope([]);
    assert.deepEqual(empty.allowedSources, []);
    assert.equal(citeAgainst(empty.allowedSources, undefined), "ok");
    assert.equal(citeAgainst(empty.allowedSources, []), "ok");
    assert.equal(citeAgainst(empty.allowedSources, ["https://example.com/"]), "citation_mismatch");
    const listed = storedEnvelope(["https://example.com/a"]);
    assert.equal(citeAgainst(listed.allowedSources, ["https://example.com/a"]), "ok");
    assert.equal(citeAgainst(listed.allowedSources, ["https://example.com/b"]), "citation_mismatch");
  });

  it("rejects non-canonical spellings without treating that as an address check", () => {
    const rejected = [
      "http://example.com/",
      "https://user@example.com/",
      "https://printer.local/",
      "https://a.localhost/",
      "https://a.internal/",
      "https://a.invalid/",
      "https://127.0.0.1/",
      "https://example.com/%7E",
      "https://example.com/%7e",
      "https://example.com/?",
      "https://example.com/#",
      "https://example.com/%2e%2e/",
      `https://example.com/\u200b`,
      `https://example.com/?t=${["admrn", "gb"].join("_")}_${"a".repeat(43)}`,
      `https://example.com/${"a".repeat(281)}`,
    ];
    for (const value of rejected) assert.equal(admitSources([value]), "rejected", value);
    const accepted = storedEnvelope(["https://example.com/%20", "https://notlocalhost.com/"]);
    assert.deepEqual(accepted.allowedSources, ["https://example.com/%20", "https://notlocalhost.com/"]);
  });

  it("grants no network authority", () => {
    const calls: string[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = (() => {
      calls.push("fetch");
      return Promise.reject(new Error("unexpected fetch"));
    }) as typeof fetch;
    try {
      const stored = storedEnvelope(["https://rebind.example/path"]);
      assert.equal(calls.length, 0);
      assert.equal(stored.allowedSources[0], "https://rebind.example/path");
      assert.equal(new URL(stored.allowedSources[0]).hostname, "rebind.example");
      for (const flag of AUTHORITY_FLAGS) assert.equal(stored.authority[flag], false);
      assert.equal(stored.json.includes("true"), false);
      assert.equal(/\bfetch\s*\(|\bdns\b|\blookup\b|\bconnect\s*\(/.test(bridgeSketch()), false);
    } finally {
      globalThis.fetch = original;
    }
  });
});

const RUNTIME_START = Date.parse("2026-10-26T12:00:00.000Z");
const RUNTIME_DAY = 86_400_000;
const EMPTY_SCOPE = { allowed_sources: [], allowed_resources: [] };
const runtimeDatabases: SqliteD1[] = [];

afterEach(() => {
  for (const db of runtimeDatabases.splice(0)) db.sqlite.close();
  mock.restoreAll();
});

function runtime() {
  const d1 = new SqliteD1();
  runtimeDatabases.push(d1);
  let now = RUNTIME_START;
  pinSqliteNow(d1.sqlite, () => now);
  return { d1, service: new ItemLifecycle(d1.binding(), () => now), advance: (ms: number) => { now += ms; } };
}

function openInput(key: string, scope: unknown = EMPTY_SCOPE, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { idempotency_key: key, kind: "task", title: "Envelope title", body: "Envelope body", scope, ...extra };
}

function refusedWith(expected: string) {
  return (error: unknown) => error instanceof LifecycleError && error.code === expected;
}

type AuditRow = { event: string; actor: string; item_id: string | null; envelope_sha256: string | null; reason: string | null; occurred_at: string };

function auditRows(d1: SqliteD1): AuditRow[] {
  return d1.sqlite.prepare("SELECT event, actor, item_id, envelope_sha256, reason, occurred_at FROM item_audit ORDER BY seq").all() as unknown as AuditRow[];
}

function rejections(d1: SqliteD1): (string | null)[][] {
  return auditRows(d1).filter((row) => row.event === "envelope_rejected").map((row) => [row.item_id, row.reason]);
}

function storedId(n: number): string {
  return `item_dddddddd-dddd-4ddd-8ddd-${String(n).padStart(12, "0")}`;
}

/** A row written outside the service: legacy (null), malformed, mismatched, or flagged. Inserts are allowed; envelope updates are not. */
function insertStored(d1: SqliteD1, id: string, state: "open" | "claimed" | "submitted", json: string | null, sha256: string | null, deadline = "2099-01-01T00:00:00.000Z"): void {
  const at = new Date(RUNTIME_START).toISOString();
  d1.sqlite.prepare(`INSERT INTO item (
    id, sender, recipient, kind, title, body, state, deadline_at, result, sources,
    idempotency_key, request_sha256, created_at, claimed_at, submitted_at, updated_at,
    envelope_json, envelope_sha256
  ) VALUES (?, 'dot', 'grok_bot', 'task', 'Stored title', 'Stored body', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, state, deadline,
    state === "submitted" ? "Stored result" : null,
    state === "submitted" ? "[]" : null,
    `req_stored_${id.slice(-12)}`, "c".repeat(64), at,
    state === "open" ? null : at,
    state === "submitted" ? at : null,
    at, json, sha256,
  );
}

const PINNED = pinnedEnvelope();
const FLAGGED = PINNED.replace("\"spending\":false", "\"spending\":true");
const SPACED = JSON.stringify(JSON.parse(PINNED), null, 1);
const STORED_CASES = [
  { name: "pre-envelope", json: null, sha256: null, expected: "missing_envelope" },
  { name: "malformed", json: "{", sha256: digest("{"), expected: "digest_mismatch" },
  { name: "mismatched digest", json: PINNED, sha256: "ab".repeat(32), expected: "digest_mismatch" },
  { name: "flag true", json: FLAGGED, sha256: digest(FLAGGED), expected: "flag_not_false" },
  { name: "non-canonical bytes", json: SPACED, sha256: digest(SPACED), expected: "digest_mismatch" },
] as const;

describe("authority envelope runtime", () => {
  it("stores the pinned empty envelope bytes and digest and fetches nothing", async () => {
    const fetch = mock.method(globalThis, "fetch", () => { throw new Error("No network allowed"); });
    const { d1, service } = runtime();
    const opened = await service.openItem("dot", openInput("req_runtime_pinned"));
    const row = d1.sqlite.prepare("SELECT envelope_json, envelope_sha256, request_sha256 FROM item WHERE id = ?").get(opened.item.id) as {
      envelope_json: string;
      envelope_sha256: string;
      request_sha256: string;
    };
    assert.equal(row.envelope_json, PINNED);
    assert.equal(row.envelope_sha256, digest(PINNED));
    assert.equal(opened.item.envelope_sha256, digest(PINNED));
    assert.deepEqual(opened.item.envelope, JSON.parse(PINNED));
    const request = JSON.stringify({
      body: "Envelope body",
      deadline_minutes: ITEM_DEADLINE_DEFAULT_MINUTES,
      envelope_sha256: digest(PINNED),
      kind: "task",
      title: "Envelope title",
    });
    assert.equal(row.request_sha256, digest(request));
    const listed = await service.openItem("dot", openInput("req_runtime_listed", { allowed_sources: ["https://rebind.example/path"], allowed_resources: [] }));
    assert.deepEqual(listed.item.envelope?.scope.allowed_sources, ["https://rebind.example/path"]);
    assert.equal(JSON.stringify(listed.item.envelope).includes("true"), false);
    assert.equal(fetch.mock.callCount(), 0);
    assert.deepEqual(auditRows(d1).map((entry) => [entry.event, entry.actor, entry.item_id, entry.envelope_sha256, entry.reason, entry.occurred_at]), [
      ["item_opened", "dot", opened.item.id, digest(PINNED), null, opened.item.created_at],
      ["item_opened", "dot", listed.item.id, listed.item.envelope_sha256, null, listed.item.created_at],
    ]);
  });

  it("matches the note's grammar sketch and builds the same canonical bytes", () => {
    const samples = [
      "https://example.com/", "https://sub.example.org/path?q=1#fragment", "https://example.com/%20", "https://notlocalhost.com/",
      "https://xn--exmple-cua.com/", `https://${"a".repeat(63)}.example/PATH`, "https://example.net", "http://example.com/",
      "https://Example.com/", "https://example.com:443/", "https://example.com./", `https://${"a".repeat(64)}.example/`,
      "https://user@example.com/", "https://printer.local/", "https://a.localhost/", "https://a.internal/", "https://a.invalid/",
      "https://localhost/", "https://127.0.0.1/", "https://example.com/%7E", "https://example.com/%7e", "https://example.com/?",
      "https://example.com/#", "https://example.com/%2e%2e/", "https://example.com/\u200b", `https://example.com/${"a".repeat(281)}`,
    ];
    for (const value of samples) assert.equal(isCanonicalSource(value), canonicalSource(value) !== undefined, value);
    for (const sources of [[], ["https://b.example/path", "https://a.example/"], ["https://example.com/%20"]]) {
      const built = buildEnvelope({ allowed_sources: sources, allowed_resources: [] }, undefined);
      const sketched = admitSources(sources);
      assert.ok(built.ok);
      assert.ok(sketched !== "rejected");
      assert.equal(built.json, sketched.json);
    }
  });

  it("sorts the stored lists and audits each rejected envelope without storing it", async () => {
    const { d1, service } = runtime();
    const sorted = await service.openItem("dot", openInput("req_runtime_sorted", {
      allowed_sources: ["https://b.example/path", "https://a.example/"],
      allowed_resources: ["zeta", "Alpha 1"],
    }));
    assert.deepEqual(sorted.item.envelope?.scope, {
      allowed_resources: ["Alpha 1", "zeta"],
      allowed_sources: ["https://a.example/", "https://b.example/path"],
    });
    const cases: [unknown, unknown, string][] = [
      [undefined, undefined, "wrong_type"],
      [[], undefined, "wrong_type"],
      [{ allowed_sources: [] }, undefined, "wrong_type"],
      [{ allowed_sources: "https://a.example/", allowed_resources: [] }, undefined, "wrong_type"],
      [{ allowed_sources: [7], allowed_resources: [] }, undefined, "wrong_type"],
      [{ ...EMPTY_SCOPE, extra: [] }, undefined, "unknown_key"],
      [EMPTY_SCOPE, { max_steps: 3 }, "unknown_key"],
      [EMPTY_SCOPE, null, "wrong_type"],
      [EMPTY_SCOPE, { spending: "false" }, "wrong_type"],
      [EMPTY_SCOPE, { external_actions: true }, "flag_not_false"],
      [EMPTY_SCOPE, { message_grants_authority: true }, "flag_not_false"],
      [{ allowed_sources: ["https://a.example/", "https://b.example/", "https://c.example/", "https://d.example/"], allowed_resources: [] }, undefined, "over_limit"],
      [{ allowed_sources: [], allowed_resources: ["a", "b", "c", "d"] }, undefined, "over_limit"],
      [{ allowed_sources: ["https://example.net"], allowed_resources: [] }, undefined, "non_canonical_url"],
      [{ allowed_sources: ["https://printer.local/"], allowed_resources: [] }, undefined, "non_canonical_url"],
      [{ allowed_sources: ["https://a.example/", "https://a.example/"], allowed_resources: [] }, undefined, "duplicate"],
      [{ allowed_sources: [], allowed_resources: [" padded"] }, undefined, "bad_label"],
      [{ allowed_sources: [], allowed_resources: ["trailing "] }, undefined, "bad_label"],
      [{ allowed_sources: [], allowed_resources: ["Same", "Same"] }, undefined, "duplicate"],
    ];
    for (const [index, [scope, authority, reason]] of cases.entries()) {
      // openInput's default would replace an undefined scope, so set it after the spread.
      const input = { ...openInput(`req_runtime_bad_${String(index).padStart(2, "0")}`), scope, ...(authority === undefined ? {} : { authority }) };
      await assert.rejects(service.openItem("grok_bot", input), refusedWith("envelope_rejected"), reason);
    }
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM item WHERE sender = 'grok_bot'").get()?.n, 0);
    const refused = auditRows(d1).filter((entry) => entry.event === "envelope_rejected");
    assert.deepEqual(refused.map((entry) => entry.reason), cases.map(([, , reason]) => reason));
    for (const entry of refused) {
      assert.equal(entry.actor, "grok_bot");
      assert.equal(entry.item_id, null);
      assert.equal(entry.envelope_sha256, null);
    }
  });

  it("replays the same key and canonical envelope once and conflicts on a different envelope", async () => {
    const { d1, service } = runtime();
    const listed = { allowed_sources: ["https://example.com/a"], allowed_resources: [] };
    const first = await service.openItem("dot", openInput("req_runtime_replay", listed));
    const again = await service.openItem("dot", openInput("req_runtime_replay", listed, { authority: { spending: false } }));
    assert.equal(again.replayed, true);
    assert.equal(again.item.id, first.item.id);
    await assert.rejects(service.openItem("dot", openInput("req_runtime_replay")), refusedWith("idempotency_conflict"));
    assert.deepEqual(auditRows(d1).map((entry) => entry.event), ["item_opened"]);
  });

  it("refuses claim and submit of a missing or invalid stored envelope without changing state", async () => {
    const { d1, service } = runtime();
    const expected: (string | null)[][] = [];
    for (const [index, entry] of STORED_CASES.entries()) {
      const openId = storedId(index * 2 + 1), claimedId = storedId(index * 2 + 2);
      insertStored(d1, openId, "open", entry.json, entry.sha256);
      insertStored(d1, claimedId, "claimed", entry.json, entry.sha256);
      await assert.rejects(service.claimItem("grok_bot", { item_id: openId }), refusedWith(entry.expected), entry.name);
      await assert.rejects(service.submitResult("grok_bot", { item_id: claimedId, result: "Answer" }), refusedWith(entry.expected), entry.name);
      assert.equal(itemState(d1.sqlite, openId), "open");
      assert.equal(itemState(d1.sqlite, claimedId), "claimed");
      expected.push([openId, entry.expected], [claimedId, entry.expected]);
    }
    assert.deepEqual(rejections(d1), expected);
    // Keyed on the item: a retry returns the same result and adds nothing.
    await assert.rejects(service.claimItem("grok_bot", { item_id: storedId(1) }), refusedWith("missing_envelope"));
    assert.equal(rejections(d1).length, expected.length);
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM item WHERE claimed_at IS NOT NULL AND state = 'open'").get()?.n, 0);
  });

  it("fails cancel and review closed on an invalid stored envelope and still cancels a pre-envelope row", async () => {
    const { d1, service } = runtime();
    insertStored(d1, storedId(21), "open", "{", digest("{"));
    insertStored(d1, storedId(22), "submitted", FLAGGED, digest(FLAGGED));
    insertStored(d1, storedId(23), "open", null, null);
    await assert.rejects(service.cancelItem("dot", { item_id: storedId(21) }), refusedWith("digest_mismatch"));
    assert.equal(itemState(d1.sqlite, storedId(21)), "open");
    await assert.rejects(service.reviewResult("dot", { item_id: storedId(22), decision: "accept" }), refusedWith("flag_not_false"));
    assert.equal(itemState(d1.sqlite, storedId(22)), "submitted");
    const cancelled = await service.cancelItem("dot", { item_id: storedId(23) });
    assert.equal(cancelled.item.state, "cancelled");
    assert.equal(cancelled.item.envelope, null);
    assert.equal(cancelled.item.envelope_sha256, null);
    assert.deepEqual(auditRows(d1).map((entry) => [entry.event, entry.item_id, entry.reason]), [
      ["envelope_rejected", storedId(21), "digest_mismatch"],
      ["envelope_rejected", storedId(22), "flag_not_false"],
      ["item_cancelled", storedId(23), null],
    ]);
  });

  it("admits only exact listed citations and leaves a miss claimed", async () => {
    const { d1, service } = runtime();
    const listed = await service.openItem("dot", openInput("req_runtime_cite_1", { allowed_sources: ["https://example.com/a"], allowed_resources: [] }));
    const empty = await service.openItem("dot", openInput("req_runtime_cite_2"));
    for (const opened of [listed, empty]) await service.claimItem("grok_bot", { item_id: opened.item.id });
    await assert.rejects(service.submitResult("grok_bot", { item_id: listed.item.id, result: "Answer", sources: ["https://example.com/b"] }), refusedWith("citation_mismatch"));
    await assert.rejects(service.submitResult("grok_bot", { item_id: empty.item.id, result: "Answer", sources: ["https://example.com/a"] }), refusedWith("citation_mismatch"));
    assert.equal(itemState(d1.sqlite, listed.item.id), "claimed");
    assert.equal(itemState(d1.sqlite, empty.item.id), "claimed");
    const cited = await service.submitResult("grok_bot", { item_id: listed.item.id, result: "Answer", sources: ["https://example.com/a"] });
    assert.equal(cited.item.state, "submitted");
    assert.equal(cited.item.citations_are_claims_until_independently_checked, true);
    assert.equal(cited.item.result_label, "unverified");
    assert.equal((await service.submitResult("grok_bot", { item_id: empty.item.id, result: "Answer" })).item.state, "submitted");
    assert.deepEqual(rejections(d1), [[listed.item.id, "citation_mismatch"], [empty.item.id, "citation_mismatch"]]);
  });

  it("caps envelope rejections at 20 per actor and UTC day without blocking a valid open", async () => {
    const { d1, service, advance } = runtime();
    insertStored(d1, storedId(31), "open", null, null);
    const flagged = (index: number) => openInput(`req_runtime_cap_${String(index).padStart(2, "0")}`, EMPTY_SCOPE, { authority: { spending: true } });
    for (let index = 0; index < 20; index += 1) {
      await assert.rejects(service.openItem("grok_bot", flagged(index)), refusedWith("envelope_rejected"));
    }
    assert.equal(auditRows(d1).length, 20);
    await assert.rejects(service.openItem("grok_bot", flagged(20)), refusedWith("rate_limited"));
    assert.equal(auditRows(d1).length, 20);
    const valid = await service.openItem("grok_bot", openInput("req_runtime_cap_valid"));
    assert.equal(valid.replayed, false);
    assert.equal(auditRows(d1).length, 21);
    // A pre-envelope claim or submit keeps missing_envelope after the cap, and a failing read is rate_limited.
    await assert.rejects(service.claimItem("grok_bot", { item_id: storedId(31) }), refusedWith("missing_envelope"));
    await assert.rejects(service.submitResult("grok_bot", { item_id: storedId(31), result: "Answer" }), refusedWith("missing_envelope"));
    await assert.rejects(service.getItem("grok_bot", { item_id: storedId(31) }), refusedWith("rate_limited"));
    assert.equal(auditRows(d1).length, 21);
    assert.equal(itemState(d1.sqlite, storedId(31)), "open");
    // The cap is per UTC day.
    advance(12 * 3_600_000);
    await assert.rejects(service.openItem("grok_bot", flagged(21)), refusedWith("envelope_rejected"));
    assert.equal(auditRows(d1).length, 22);
  });

  it("refuses content for a failing stored envelope, lists it as a stub, and stamps only deliverable rows", async () => {
    const { d1, service } = runtime();
    const valid = await service.openItem("dot", openInput("req_runtime_list_1", {
      allowed_sources: ["https://example.com/listed"],
      allowed_resources: ["Label one"],
    }));
    const failing = STORED_CASES.map((entry, index) => {
      insertStored(d1, storedId(41 + index), "open", entry.json, entry.sha256);
      return storedId(41 + index);
    });
    for (const id of failing) {
      await assert.rejects(service.getItem("grok_bot", { item_id: id }), refusedWith("envelope_rejected"));
      await assert.rejects(service.getItem("dot", { item_id: id }), refusedWith("envelope_rejected"));
    }
    const inbox = await service.listItems("grok_bot", { box: "inbox" });
    const entries = new Map(inbox.items.map((entry) => [entry.id, entry] as const));
    assert.equal(entries.size, failing.length + 1);
    for (const id of failing) {
      assert.deepEqual(entries.get(id), { id, state: "open", untrusted: true, owner_approval: "required", envelope_status: "rejected" });
    }
    assert.equal(entries.get(valid.item.id)?.title, "Envelope title");
    assert.equal(entries.get(valid.item.id)?.envelope_sha256, valid.item.envelope_sha256);
    assert.equal(inbox.pending_items.length, failing.length + 1);
    for (const hidden of ["https://example.com/listed", "Label one", "Stored title", "envelope_json"]) {
      assert.equal(JSON.stringify(inbox).includes(hidden), false, hidden);
    }
    const stamped = d1.sqlite.prepare("SELECT id FROM item WHERE delivered_at IS NOT NULL").all().map((entry) => String(entry.id));
    assert.deepEqual(stamped, [valid.item.id]);
    const delivered = () => auditRows(d1).filter((entry) => entry.event === "item_delivered");
    assert.deepEqual(delivered().map((entry) => [entry.actor, entry.item_id, entry.envelope_sha256]), [["grok_bot", valid.item.id, valid.item.envelope_sha256]]);
    // One keyed refusal per reader, item, and reason. The list stubs found them already recorded.
    assert.equal(rejections(d1).length, failing.length * 2);
    const more = [
      await service.openItem("dot", openInput("req_runtime_list_2")),
      await service.openItem("dot", openInput("req_runtime_list_3")),
    ];
    await service.listItems("grok_bot", { box: "inbox" });
    assert.deepEqual(delivered().slice(1).map((entry) => entry.item_id).sort(), more.map((opened) => opened.item.id).sort());
    await service.listItems("grok_bot", { box: "inbox" });
    await service.getItem("grok_bot", { item_id: valid.item.id });
    assert.equal(delivered().length, 3);
  });

  it("records item_expired once at the deadline when claim, cancel, and retention all observe it", async () => {
    const { d1, service, advance } = runtime();
    const opened = await service.openItem("dot", openInput("req_runtime_expiry", EMPTY_SCOPE, { deadline_minutes: 5 }));
    advance(6 * 60_000);
    await assert.rejects(service.claimItem("grok_bot", { item_id: opened.item.id }), refusedWith("deadline_passed"));
    await assert.rejects(service.cancelItem("dot", { item_id: opened.item.id }), refusedWith("deadline_passed"));
    const before = auditRows(d1).length;
    assert.equal(await sweepExpiredItems(d1.binding(), RUNTIME_START + 7 * 60_000), 0);
    assert.equal(auditRows(d1).length, before);
    assert.equal(itemState(d1.sqlite, opened.item.id), "expired");
    const expired = auditRows(d1).filter((entry) => entry.event === "item_expired");
    assert.deepEqual(expired.map((entry) => [entry.actor, entry.item_id, entry.occurred_at]), [["grok_bot", opened.item.id, opened.item.deadline_at]]);
  });

  it("records item_expired once at the deadline when claim, submit, and cancel refuse an unusable stored envelope", async () => {
    const { d1, service, advance } = runtime();
    const deadline = new Date(RUNTIME_START + 5 * 60_000).toISOString();
    const ids = STORED_CASES.map((entry, index) => {
      insertStored(d1, storedId(51 + index), "open", entry.json, entry.sha256, deadline);
      return storedId(51 + index);
    });
    advance(6 * 60_000);
    for (const [index, entry] of STORED_CASES.entries()) {
      const id = ids[index];
      await assert.rejects(service.claimItem("grok_bot", { item_id: id }), refusedWith(entry.expected), entry.name);
      await assert.rejects(service.submitResult("grok_bot", { item_id: id, result: "Answer" }), refusedWith(entry.expected), entry.name);
      // Cancel fails closed only on an invalid envelope. A pre-envelope row reaches deadline_passed.
      await assert.rejects(service.cancelItem("dot", { item_id: id }), refusedWith(entry.json === null ? "deadline_passed" : entry.expected), entry.name);
      assert.equal(itemState(d1.sqlite, id), "open");
    }
    const expired = () => auditRows(d1).filter((entry) => entry.event === "item_expired").map((entry) => [entry.actor, entry.item_id, entry.envelope_sha256, entry.occurred_at]);
    // The claim observed each deadline first. Submit and cancel observed it again and added nothing.
    const recorded = STORED_CASES.map((entry, index) => ["grok_bot", ids[index], entry.sha256, deadline]);
    assert.deepEqual(expired(), recorded);
    // Claim and submit share the recipient's keyed row. A fail-closed cancel adds the sender's.
    assert.deepEqual(auditRows(d1).filter((entry) => entry.event === "envelope_rejected").map((entry) => [entry.actor, entry.item_id, entry.reason]), STORED_CASES.flatMap((entry, index) => [
      ["grok_bot", ids[index], entry.expected],
      ...(entry.json === null ? [] : [["dot", ids[index], entry.expected]]),
    ]));
    // Retention stores the expiry and adds no second fact.
    assert.equal(await sweepExpiredItems(d1.binding(), RUNTIME_START + 7 * 60_000), 0);
    assert.deepEqual(expired(), recorded);
    for (const id of ids) assert.equal(itemState(d1.sqlite, id), "expired");
  });

  it("keeps the rejection cap when a refused claim records item_expired, and a refused review records none", async () => {
    const { d1, service, advance } = runtime();
    const deadline = new Date(RUNTIME_START + 5 * 60_000).toISOString();
    insertStored(d1, storedId(61), "open", FLAGGED, digest(FLAGGED), deadline);
    for (let index = 0; index < 20; index += 1) {
      const input = openInput(`req_runtime_expiry_cap_${String(index).padStart(2, "0")}`, EMPTY_SCOPE, { authority: { spending: true } });
      await assert.rejects(service.openItem("grok_bot", input), refusedWith("envelope_rejected"));
    }
    advance(6 * 60_000);
    const expired = () => auditRows(d1).filter((entry) => entry.event === "item_expired").map((entry) => [entry.actor, entry.item_id, entry.occurred_at]);
    // A review batch has no expiry statement, refused or not.
    await assert.rejects(service.reviewResult("dot", { item_id: storedId(61), decision: "accept" }), refusedWith("flag_not_false"));
    assert.deepEqual(expired(), []);
    // grok_bot is at the cap. The explicit result holds and adds no envelope_rejected. Expiry is not a rejection.
    const refused = rejections(d1).length;
    await assert.rejects(service.claimItem("grok_bot", { item_id: storedId(61) }), refusedWith("flag_not_false"));
    assert.equal(rejections(d1).length, refused);
    assert.deepEqual(expired(), [["grok_bot", storedId(61), deadline]]);
    assert.equal(itemState(d1.sqlite, storedId(61)), "open");
  });

  it("writes ordinary audit rows without counting item_audit", async () => {
    const { d1, service } = runtime();
    const opened = await service.openItem("dot", openInput("req_runtime_count"));
    await service.claimItem("grok_bot", { item_id: opened.item.id });
    await service.submitResult("grok_bot", { item_id: opened.item.id, result: "Answer" });
    await service.reviewResult("dot", { item_id: opened.item.id, decision: "accept" });
    assert.deepEqual(auditRows(d1).map((entry) => [entry.event, entry.actor]), [
      ["item_opened", "dot"], ["item_claimed", "grok_bot"], ["item_submitted", "grok_bot"], ["item_accepted", "dot"],
    ]);
    assert.equal(d1.prepared.some((sql) => /count\(\*\)\s+FROM\s+item_audit/i.test(sql)), false);
  });

  it("prunes audit rows after 90 days in their own batch and keeps them past the 30-day item purge", async () => {
    const { d1, service, advance } = runtime();
    const opened = await service.openItem("dot", openInput("req_runtime_prune"));
    await service.cancelItem("dot", { item_id: opened.item.id });
    assert.equal(await sweepExpiredItems(d1.binding(), RUNTIME_START + 31 * RUNTIME_DAY), 1);
    assert.equal(await pruneAuditRows(d1.binding(), RUNTIME_START + 31 * RUNTIME_DAY), 0);
    assert.deepEqual(auditRows(d1).map((entry) => entry.event), ["item_opened", "item_cancelled"]);
    advance(91 * RUNTIME_DAY);
    const fresh = await service.openItem("dot", openInput("req_runtime_prune_2"));
    // A prune that also matches a row younger than 90 days by the database clock aborts only itself.
    await assert.rejects(pruneAuditRows(d1.binding(), RUNTIME_START + 200 * RUNTIME_DAY), /item_audit_append_only/);
    assert.equal(auditRows(d1).length, 3);
    assert.equal(await pruneAuditRows(d1.binding(), RUNTIME_START + 91 * RUNTIME_DAY), 2);
    assert.deepEqual(auditRows(d1).map((entry) => [entry.event, entry.item_id]), [["item_opened", fresh.item.id]]);
    await service.cancelItem("dot", { item_id: fresh.item.id });
    assert.deepEqual(auditRows(d1).map((entry) => entry.event), ["item_opened", "item_cancelled"]);
  });

  it("logs a rejection with the participant and fixed reason only", async () => {
    const { service } = runtime();
    const lines: string[] = [];
    mock.method(console, "log", (...args: unknown[]) => { lines.push(args.map(String).join(" ")); });
    mock.method(console, "error", (...args: unknown[]) => { lines.push(args.map(String).join(" ")); });
    const input = openInput("req_runtime_log_1", { allowed_sources: ["https://secret.example/path?q=1"], allowed_resources: ["Hidden label"] }, { authority: { delegation: true } });
    await assert.rejects(service.openItem("dot", input), refusedWith("envelope_rejected"));
    assert.equal(lines.length, 1);
    assert.deepEqual(JSON.parse(lines[0] ?? "{}"), { message: "bridge event", event: "envelope.rejected", participant: "dot", reason: "flag_not_false" });
    for (const hidden of ["secret.example", "Hidden label", "Envelope title", "Envelope body", "req_runtime_log_1"]) {
      assert.equal(lines.join("\n").includes(hidden), false, hidden);
    }
  });

  it("reads a stored envelope back only when its bytes rebuild", async () => {
    const built = buildEnvelope({ allowed_sources: ["https://example.com/a"], allowed_resources: ["Label"] }, { spending: false });
    assert.ok(built.ok);
    const valid = await checkStoredEnvelope(built.json, digest(built.json));
    assert.equal(valid.status, "valid");
    assert.deepEqual(await checkStoredEnvelope(null, null), { status: "missing" });
    for (const entry of STORED_CASES) {
      if (entry.json === null) continue;
      assert.deepEqual(await checkStoredEnvelope(entry.json, entry.sha256), { status: "invalid", reason: entry.expected }, entry.name);
    }
    assert.deepEqual(await checkStoredEnvelope(built.json, null), { status: "invalid", reason: "digest_mismatch" });
  });
});
