/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { checkMigrations, MIGRATION_SHA256 } from "../scripts/migration-guard.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts/migration-guard.mjs");
const MIGRATIONS = join(ROOT, "migrations");

function directory(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "migration-guard-"));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  return dir;
}

function digest(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** A local run must not inherit a CI base. The child then has to choose one itself. */
function localEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env.GITHUB_ACTIONS;
  delete env.GITHUB_BASE_REF;
  delete env.MIGRATION_BASE;
  return env;
}

function runGuard(args: string[], env: NodeJS.ProcessEnv = localEnv()): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, args, { cwd: ROOT, encoding: "utf8", env });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

describe("migration freeze guard", () => {
  it("accepts the released files from the command and from the checker", () => {
    const result = runGuard([SCRIPT]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "checked 8 migration(s)\n");
    assert.deepEqual(checkMigrations(MIGRATIONS), []);
    assert.equal(Object.hasOwn(MIGRATION_SHA256, "0006_authority_envelope.sql"), true);
    assert.equal(
      MIGRATION_SHA256["0006_authority_envelope.sql"],
      digest(readFileSync(join(MIGRATIONS, "0006_authority_envelope.sql"), "utf8")),
    );
    assert.deepEqual(Object.keys(MIGRATION_SHA256).sort(), [
      "0001_owner_lock.sql",
      "0002_item_lifecycle.sql",
      "0003_participant_credentials.sql",
      "0004_connect_code.sql",
      "0005_item_receipt.sql",
      "0006_authority_envelope.sql",
    ]);
  });

  it("rejects a changed file, an unpinned file, a missing pin, and an unmarked structural change", () => {
    const original = readFileSync(join(MIGRATIONS, "0005_item_receipt.sql"), "utf8");
    const changed = directory({ "0005_item_receipt.sql": `${original}\n-- edited\n` });
    assert.deepEqual(checkMigrations(changed, { "0005_item_receipt.sql": MIGRATION_SHA256["0005_item_receipt.sql"] }), [
      "0005_item_receipt.sql hash does not match the pin",
    ]);
    rmSync(changed, { recursive: true, force: true });

    const extra = directory({ "0006_extra.sql": "SELECT 1;\n" });
    assert.deepEqual(checkMigrations(extra, {}), ["0006_extra.sql is not pinned"]);
    rmSync(extra, { recursive: true, force: true });

    const missing = directory({});
    assert.deepEqual(checkMigrations(missing, { "0005_item_receipt.sql": MIGRATION_SHA256["0005_item_receipt.sql"] }), [
      "0005_item_receipt.sql is pinned but missing",
    ]);
    rmSync(missing, { recursive: true, force: true });

    const unmarked = directory({
      "0009_drop.sql": "DROP TABLE item;\n",
      "0010_rename.sql": "ALTER TABLE item RENAME TO item_old;\n",
      "0011_word.sql": "-- not dropped and not renamed\nSELECT 1;\n",
    });
    const problems = checkMigrations(unmarked, {
      "0009_drop.sql": "unused",
      "0010_rename.sql": "unused",
      "0011_word.sql": "unused",
    });
    assert.equal(problems.some((problem) => problem.startsWith("0009_drop.sql hash")), true);
    assert.equal(problems.some((problem) => problem.includes("0009_drop.sql changes structure")), true);
    assert.equal(problems.some((problem) => problem.includes("0010_rename.sql changes structure")), true);
    assert.equal(problems.some((problem) => problem.includes("0011_word.sql changes structure")), false);
    rmSync(unmarked, { recursive: true, force: true });

    const marked = "-- apply: single-request\nDROP TABLE item;\n";
    const okDir = directory({ "0009_drop.sql": marked });
    const pins = { "0009_drop.sql": "placeholder" };
    const accepted = checkMigrations(okDir, pins).filter((problem) => problem.includes("structure") || problem.includes("transaction"));
    assert.deepEqual(accepted, []);
    rmSync(okDir, { recursive: true, force: true });

    const wrapped = directory({ "0009_drop.sql": `-- apply: single-request\nBEGIN\nDROP TABLE item;\nCOMMIT\n` });
    assert.equal(
      checkMigrations(wrapped, { "0009_drop.sql": "placeholder" }).some((problem) => problem.includes("transaction")),
      true,
    );
    rmSync(wrapped, { recursive: true, force: true });

    const trigger = directory({
      "0009_drop.sql": "-- apply: single-request\nDROP TABLE item;\nCREATE TRIGGER item_example BEFORE UPDATE ON item\nBEGIN SELECT RAISE(ABORT, 'no'); END;\n",
    });
    const triggerProblems = checkMigrations(trigger, { "0009_drop.sql": "placeholder" });
    assert.equal(triggerProblems.some((problem) => problem.includes("transaction")), false);
    assert.equal(triggerProblems.some((problem) => problem.includes("structure")), false);
    rmSync(trigger, { recursive: true, force: true });
  });

  it("exits 1 for an unpinned migration from the real path and from a symlink", () => {
    const migrations = directory({ "0099_unpinned.sql": "SELECT 1;\n" });
    const bin = mkdtempSync(join(tmpdir(), "migration-guard-"));
    const link = join(bin, "guard.mjs");
    symlinkSync(SCRIPT, link);
    try {
      for (const command of [SCRIPT, link]) {
        const result = runGuard([command, "--migrations", migrations]);
        assert.equal(result.status, 1, result.stdout + result.stderr);
        assert.match(result.stderr, /0099_unpinned\.sql is not pinned/);
      }
    } finally {
      rmSync(migrations, { recursive: true, force: true });
      rmSync(bin, { recursive: true, force: true });
    }
  });

  it("rejects a released migration that was edited together with its pin", () => {
    const releasedText = "SELECT 1;\n";
    const editedText = "SELECT 2;\n";
    const released = directory({ "0005_item_receipt.sql": releasedText });
    const candidate = directory({ "0005_item_receipt.sql": editedText });
    try {
      const problems = checkMigrations(candidate, { "0005_item_receipt.sql": digest(editedText) }, released);
      assert.equal(problems.includes("0005_item_receipt.sql differs from the released migration"), true);
    } finally {
      rmSync(released, { recursive: true, force: true });
      rmSync(candidate, { recursive: true, force: true });
    }
  });

  it("accepts a new migration when every released file is unchanged", () => {
    const released = directory({});
    const candidate = directory({});
    try {
      for (const name of ["0001_owner_lock.sql", "0002_item_lifecycle.sql", "0003_participant_credentials.sql", "0004_connect_code.sql"]) {
        const bytes = readFileSync(join(MIGRATIONS, name));
        writeFileSync(join(released, name), bytes);
        writeFileSync(join(candidate, name), bytes);
      }
      writeFileSync(join(candidate, "0005_item_receipt.sql"), readFileSync(join(MIGRATIONS, "0005_item_receipt.sql")));
      writeFileSync(join(candidate, "0006_authority_envelope.sql"), readFileSync(join(MIGRATIONS, "0006_authority_envelope.sql")));
      const result = runGuard([SCRIPT, "--migrations", candidate, "--base-dir", released]);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "checked 6 migration(s), 4 released unchanged\n");
    } finally {
      rmSync(released, { recursive: true, force: true });
      rmSync(candidate, { recursive: true, force: true });
    }
  });

  it("rejects a git-base migration whose working copy changed", () => {
    const rev = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" });
    assert.equal(rev.status, 0, rev.stderr ?? "");
    const candidate = directory({});
    try {
      for (const name of Object.keys(MIGRATION_SHA256)) {
        writeFileSync(join(candidate, name), readFileSync(join(MIGRATIONS, name)));
      }
      const target = join(candidate, "0005_item_receipt.sql");
      writeFileSync(target, `${readFileSync(target, "utf8")}\n-- edited\n`);
      const result = runGuard([SCRIPT, "--migrations", candidate, "--base", (rev.stdout ?? "").trim()]);
      assert.equal(result.status, 1, result.stdout);
      assert.match(result.stderr, /0005_item_receipt.sql differs from the released migration/);
    } finally {
      rmSync(candidate, { recursive: true, force: true });
    }
  });

  it("accepts the current commit as a base when released files are unchanged", () => {
    const rev = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" });
    assert.equal(rev.status, 0, rev.stderr ?? "");
    const sha = (rev.stdout ?? "").trim();
    const result = runGuard([SCRIPT, "--base", sha]);
    assert.equal(result.status, 0, result.stderr);
    const listed = spawnSync("git", ["ls-tree", "-r", "--name-only", sha, "migrations"], { cwd: ROOT, encoding: "utf8" });
    assert.equal(listed.status, 0, listed.stderr ?? "");
    const released = listed.stdout.split("\n").filter((line) => line.endsWith(".sql")).length;
    const total = readdirSync(MIGRATIONS).filter((name) => name.endsWith(".sql")).length;
    assert.equal(result.stdout, `checked ${total} migration(s), ${released} released unchanged\n`);
  });

  it("accepts an unreleased migration when 0001-0006 stay pinned", () => {
    assert.deepEqual(Object.keys(MIGRATION_SHA256).sort(), [
      "0001_owner_lock.sql",
      "0002_item_lifecycle.sql",
      "0003_participant_credentials.sql",
      "0004_connect_code.sql",
      "0005_item_receipt.sql",
      "0006_authority_envelope.sql",
    ]);
    const released = directory({});
    const candidate = directory({});
    try {
      for (const name of Object.keys(MIGRATION_SHA256)) {
        const bytes = readFileSync(join(MIGRATIONS, name));
        writeFileSync(join(released, name), bytes);
        writeFileSync(join(candidate, name), bytes);
      }
      writeFileSync(join(candidate, "0007_next.sql"), "SELECT 1;\n");
      const result = runGuard([SCRIPT, "--migrations", candidate, "--base-dir", released]);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "checked 7 migration(s), 6 released unchanged\n");
    } finally {
      rmSync(released, { recursive: true, force: true });
      rmSync(candidate, { recursive: true, force: true });
    }
  });

  it("fails closed in CI when the migration base cannot be resolved", () => {
    const missing = runGuard([SCRIPT], { ...localEnv(), GITHUB_ACTIONS: "true" });
    assert.equal(missing.status, 1, missing.stdout);
    assert.match(missing.stderr, /migration base is unresolved/);

    const zero = runGuard([SCRIPT, "--base", "0".repeat(40)]);
    assert.equal(zero.status, 1, zero.stdout);
    assert.match(zero.stderr, /migration base is unresolved/);

    const fixture = directory({ "0005_item_receipt.sql": "SELECT 1;\n" });
    try {
      const asPath = runGuard([SCRIPT, "--base", fixture]);
      assert.equal(asPath.status, 1, asPath.stdout);
      assert.match(asPath.stderr, /migration base is unresolved/);
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  });

  it("fails closed when the base directory has no released migrations", () => {
    const released = directory({});
    const candidate = directory({});
    try {
      for (const name of Object.keys(MIGRATION_SHA256)) {
        writeFileSync(join(candidate, name), readFileSync(join(MIGRATIONS, name)));
      }
      const result = runGuard([SCRIPT, "--migrations", candidate, "--base-dir", released]);
      assert.equal(result.status, 1, result.stdout);
      assert.match(result.stderr, /released migration comparison is empty/);
    } finally {
      rmSync(released, { recursive: true, force: true });
      rmSync(candidate, { recursive: true, force: true });
    }
  });

  it("rejects an altered migration when a directory spoofs the base commit", () => {
    const rev = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" });
    assert.equal(rev.status, 0, rev.stderr ?? "");
    const sha = (rev.stdout ?? "").trim();
    assert.match(sha, /^[0-9a-f]{40}$/);
    const spoof = join(ROOT, sha);
    const candidate = directory({});
    const edited = `${readFileSync(join(MIGRATIONS, "0005_item_receipt.sql"), "utf8")}\n-- edited\n`;
    mkdirSync(spoof);
    try {
      for (const name of Object.keys(MIGRATION_SHA256)) {
        writeFileSync(join(candidate, name), readFileSync(join(MIGRATIONS, name)));
      }
      writeFileSync(join(candidate, "0005_item_receipt.sql"), edited);
      writeFileSync(join(spoof, "0005_item_receipt.sql"), edited);
      const result = runGuard([SCRIPT, "--migrations", candidate, "--base", sha]);
      assert.equal(result.status, 1, result.stdout);
      assert.match(result.stderr, /0005_item_receipt.sql differs from the released migration/);
    } finally {
      rmSync(candidate, { recursive: true, force: true });
      rmSync(spoof, { recursive: true, force: true });
    }
  });
});
