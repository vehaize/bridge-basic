/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { verifyGrokBearer } from "../src/grok-bearer.ts";
import { SqliteD1 } from "./d1-sqlite.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts/grok-credential.mjs");
const TOKEN = /^admrn_gb_[A-Za-z0-9_-]{43}$/;
const EMAIL = "synthetic-owner@example.invalid";
const OWNER = "2026-10-22T00:00:00.000Z";
const directories: string[] = [];
const databases: SqliteD1[] = [];

function run(args: string[], cwd = ROOT): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [SCRIPT, ...args], { cwd, encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function directory(): string {
  const created = mkdtempSync(join(tmpdir(), "grok-credential-"));
  directories.push(created);
  return created;
}

function database(): SqliteD1 {
  const created = new SqliteD1();
  databases.push(created);
  created.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run(EMAIL, OWNER);
  return created;
}

/** D1 runs a wrangler --file as one transaction. Mirror that here. */
function applyFile(db: DatabaseSync, sql: string): void {
  db.exec("BEGIN IMMEDIATE");
  try {
    db.exec(sql);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function active(db: DatabaseSync): { id: string; token_sha256: string; owner_claimed_at: string; revoked_at: string | null }[] {
  return db.prepare(`SELECT id, token_sha256, owner_claimed_at, revoked_at
    FROM participant_credential WHERE participant = 'grok_bot' AND revoked_at IS NULL`).all() as {
    id: string;
    token_sha256: string;
    owner_claimed_at: string;
    revoked_at: string | null;
  }[];
}

afterEach(() => {
  for (const db of databases.splice(0)) db.sqlite.close();
  for (const created of directories.splice(0)) rmSync(created, { recursive: true, force: true });
});

describe("Grok credential command", () => {
  it("prints an issued token once, stores only its hash, and rotates the active row", async () => {
    const dir = directory();
    const firstPath = join(dir, "first.sql");
    const issued = run(["issue", "--out", firstPath]);
    assert.equal(issued.status, 0);
    const token = issued.stdout.trim();
    assert.match(token, TOKEN);
    assert.equal(issued.stdout, `${token}\n`);
    const hash = createHash("sha256").update(token).digest("hex");
    const sql = readFileSync(firstPath, "utf8");
    assert.equal(sql.includes(hash), true);
    assert.equal(sql.includes(token), false);
    assert.equal(issued.stderr.includes(token), false);
    assert.equal(issued.stderr.includes(hash), false);
    assert.match(issued.stderr, /does not apply it/);
    assert.equal(statSync(firstPath).mode & 0o777, 0o600);

    const d1 = database();
    applyFile(d1.sqlite, sql);
    const [row] = active(d1.sqlite);
    assert.equal(row?.token_sha256, hash);
    assert.equal(row?.owner_claimed_at, OWNER);
    assert.equal(row?.revoked_at, null);
    const request = new Request("https://bridge.example/mcp", { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(await verifyGrokBearer(request, d1.binding()), "grok_bot");

    const secondPath = join(dir, "second.sql");
    const rotated = run(["issue", "--out", secondPath]);
    assert.equal(rotated.status, 0);
    const next = rotated.stdout.trim();
    assert.notEqual(next, token);
    assert.equal(rotated.stdout, `${next}\n`);
    const nextHash = createHash("sha256").update(next).digest("hex");
    const nextSql = readFileSync(secondPath, "utf8");
    assert.equal(nextSql.includes(next), false);
    assert.equal(nextSql.includes(token), false);
    applyFile(d1.sqlite, nextSql);
    const rows = active(d1.sqlite);
    assert.equal(rows.length, 1);
    assert.equal(rows[0]?.token_sha256, nextHash);
    assert.equal(await verifyGrokBearer(request, d1.binding()), null);
    const replacement = new Request("https://bridge.example/mcp", { headers: { Authorization: `Bearer ${next}` } });
    assert.equal(await verifyGrokBearer(replacement, d1.binding()), "grok_bot");
    assert.equal(`${issued.stderr}\n${rotated.stderr}`.includes(nextHash), false);
  });

  it("rolls back an issue when the owner lock is missing and revokes without printing a secret", async () => {
    const dir = directory();
    const issuePath = join(dir, "missing-lock.sql");
    const issued = run(["issue", "--out", issuePath]);
    assert.equal(issued.status, 0);
    const token = issued.stdout.trim();
    const hash = createHash("sha256").update(token).digest("hex");
    const bare = new DatabaseSync(":memory:");
    try {
      for (const file of ["0001_owner_lock.sql", "0002_item_lifecycle.sql", "0003_participant_credentials.sql", "0004_connect_code.sql"]) {
        bare.exec(readFileSync(join(ROOT, "migrations", file), "utf8"));
      }
      bare.exec("INSERT INTO participant_credential (id, participant, kind, token_sha256, owner_claimed_at, created_at) VALUES ('credential_old', 'grok_bot', 'bearer', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '2026-10-22T00:00:00.000Z', '2026-10-22T00:00:00.000Z')");
      assert.throws(() => applyFile(bare, readFileSync(issuePath, "utf8")));
      assert.equal(bare.prepare("SELECT revoked_at FROM participant_credential WHERE id = 'credential_old'").get()?.revoked_at, null);
      assert.equal(bare.prepare("SELECT COUNT(*) AS count FROM participant_credential WHERE token_sha256 = ?").get(hash)?.count, 0);
    } finally {
      bare.close();
    }

    const d1 = database();
    d1.sqlite.prepare(`INSERT INTO participant_credential
      (id, participant, kind, token_sha256, owner_claimed_at, created_at)
      VALUES ('credential_old', 'grok_bot', 'bearer', ?, ?, ?)`).run("b".repeat(64), OWNER, OWNER);
    const revokePath = join(dir, "revoke.sql");
    const revoked = run(["revoke", "--out", revokePath]);
    assert.equal(revoked.status, 0);
    assert.equal(revoked.stdout, "");
    const revokeSql = readFileSync(revokePath, "utf8");
    assert.equal(/admrn_gb_[A-Za-z0-9_-]{43}/.test(revokeSql), false);
    assert.equal(/\b[a-f0-9]{64}\b/.test(revokeSql), false);
    assert.equal(revoked.stderr.includes(token), false);
    assert.equal(revoked.stderr.includes(hash), false);
    applyFile(d1.sqlite, revokeSql);
    assert.equal(active(d1.sqlite).length, 0);
    assert.notEqual(d1.sqlite.prepare("SELECT revoked_at FROM participant_credential WHERE id = 'credential_old'").get()?.revoked_at, null);
  });

  it("rejects malformed arguments and a token-shaped argument without echoing it", () => {
    const secret = `admrn_gb_${"c".repeat(43)}`;
    const hash = "d".repeat(64);
    const cases = [
      [],
      ["issue"],
      ["issue", "--out"],
      ["revoke", "--file", "revoke.sql"],
      ["issue", "--out", "one.sql", "two.sql"],
      ["issue", "--id", secret, "--out", "ignored.sql"],
      ["revoke", "--token", secret],
      ["issue", "--out", hash],
    ];
    for (const args of cases) {
      const result = run(args);
      assert.notEqual(result.status, 0, args.join(" "));
      assert.equal(result.stdout, "", args.join(" "));
      assert.equal(result.stderr.includes(secret), false, args.join(" "));
      assert.equal(result.stderr.includes(hash), false, args.join(" "));
      assert.match(result.stderr, /usage:|refusing a token or hash argument/, args.join(" "));
    }
    const source = readFileSync(SCRIPT, "utf8");
    assert.equal(source.includes("child_process"), false);
    assert.equal(source.includes("wrangler deploy"), false);
    assert.match(source, /getRandomValues/);
    assert.doesNotMatch(source, /Math\.random/);
  });
});
