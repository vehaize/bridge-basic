/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * CI check for released migration files. Each pinned file's bytes must match
 * its SHA-256. A file that is not in the pin map is an unreleased migration.
 * It is allowed only when every pinned file is present and matches its hash.
 * A file that already exists on the base must also match that base byte for
 * byte, so changing the pin in the same change cannot rewrite a released
 * migration. This file does not read a live database, call Wrangler, or
 * contact Cloudflare.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const STRUCTURAL = /\b(?:DROP|RENAME)\b/i;
const TRANSACTION = /\b(?:BEGIN|COMMIT)\b/i;
const SINGLE_REQUEST = "-- apply: single-request";
const UNRESOLVED = "migration base is unresolved";
const EMPTY_COMPARISON = "released migration comparison is empty";

/** SHA-256 of the committed file bytes. Adding or editing a released file must update this map. */
export const MIGRATION_SHA256 = {
  "0001_owner_lock.sql": "24f4352d19aeda9cb224deeaf00c89be6aa13081116f4b9a3f04ff8f9ea8e5f2",
  "0002_item_lifecycle.sql": "9f1cff0684a564474d2499fb46451ff920a4e7f5887492594fa88ed8910103e8",
  "0003_participant_credentials.sql": "a91af3ac1d73b02ad2355b30888ccd477770ca6b8e29f2af6c27975ae8cd6f76",
  "0004_connect_code.sql": "6d4fa181f038b4b13ffa12caa5182402dda7978bb9af408635e47a02a30b8d0a",
  "0005_item_receipt.sql": "f8d4fff2d7393ad74c9bd9e1817cf793a1ada94d053958594a9497fee48a89a7",
  "0006_authority_envelope.sql": "f60775a4e5bce7021fbec987236bcd458ab020d0701f4b5123ff85b68d190e3b",
};

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Trigger BEGIN/END is not a transaction. A real BEGIN or COMMIT still matches. */
function withoutTriggerBodies(source) {
  return source.replace(/--[^\n]*/g, "").replace(/\bCREATE\s+TRIGGER\b[\s\S]*?\bEND\s*;/gi, "");
}

/**
 * True when the pin map is non-empty and every pinned file is present and
 * matches. An unreleased file may sit beside that set. An empty pin map does
 * not make an unpinned file legal.
 * @param {string} directory
 * @param {readonly string[]} names
 * @param {Readonly<Record<string, string>>} pins
 */
function pinsHold(directory, names, pins) {
  const pinNames = Object.keys(pins);
  if (pinNames.length === 0) return false;
  for (const name of pinNames) {
    if (!names.includes(name)) return false;
    if (pins[name] !== digest(readFileSync(resolve(directory, name)))) return false;
  }
  return true;
}

function sqlNames(directory) {
  return readdirSync(directory).filter((name) => name.endsWith(".sql")).sort();
}

/**
 * Problems in a migration directory. An empty list means the directory matches
 * the pins and, when releasedDirectory is set, every released file there.
 * @param {string} directory
 * @param {Readonly<Record<string, string>>} [pins]
 * @param {string} [releasedDirectory]
 * @returns {string[]}
 */
export function checkMigrations(directory, pins = MIGRATION_SHA256, releasedDirectory) {
  const names = sqlNames(directory);
  const problems = [];
  const unreleasedAllowed = pinsHold(directory, names, pins);
  for (const name of names) {
    const bytes = readFileSync(resolve(directory, name));
    if (!Object.hasOwn(pins, name)) {
      if (!unreleasedAllowed) problems.push(`${name} is not pinned`);
    } else if (pins[name] !== digest(bytes)) {
      problems.push(`${name} hash does not match the pin`);
    }
    const source = bytes.toString("utf8");
    if (!STRUCTURAL.test(source)) continue;
    const marked = source.split(/\r?\n/).some((line) => line.trim() === SINGLE_REQUEST);
    if (!marked) problems.push(`${name} changes structure without ${SINGLE_REQUEST}`);
    if (TRANSACTION.test(withoutTriggerBodies(source))) {
      problems.push(`${name} wraps a structural change in a transaction`);
    }
  }
  for (const name of Object.keys(pins)) {
    if (!names.includes(name)) problems.push(`${name} is pinned but missing`);
  }
  if (releasedDirectory) problems.push(...releasedBytes(directory, releasedDirectory));
  return problems;
}

function releasedBytes(directory, releasedDirectory) {
  let releasedNames;
  try {
    releasedNames = sqlNames(releasedDirectory);
  } catch {
    return [UNRESOLVED];
  }
  if (releasedNames.length === 0) {
    let headNames;
    try {
      headNames = sqlNames(directory);
    } catch {
      return [UNRESOLVED];
    }
    if (headNames.length > 0) return [EMPTY_COMPARISON];
  }
  const problems = [];
  for (const name of releasedNames) {
    let released;
    try {
      released = readFileSync(resolve(releasedDirectory, name));
    } catch {
      return [UNRESOLVED];
    }
    let candidate;
    try {
      candidate = readFileSync(resolve(directory, name));
    } catch {
      problems.push(`${name} differs from the released migration`);
      continue;
    }
    if (!candidate.equals(released)) problems.push(`${name} differs from the released migration`);
  }
  return problems;
}

function parseArgs(argv) {
  let migrations = resolve(ROOT, "migrations");
  let base = "";
  let baseDir = "";
  let sawBase = false;
  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--migrations") {
      const value = argv[index + 1];
      if (!value) return { error: "missing --migrations directory" };
      migrations = resolve(value);
      index += 1;
    } else if (arg === "--base") {
      const value = argv[index + 1];
      if (!value) return { error: UNRESOLVED };
      base = value;
      sawBase = true;
      index += 1;
    } else if (arg === "--base-dir") {
      const value = argv[index + 1];
      if (!value) return { error: UNRESOLVED };
      baseDir = value;
      index += 1;
    } else {
      return { error: `unknown argument ${arg}` };
    }
  }
  if (base && baseDir) return { error: UNRESOLVED };
  if (!sawBase && !baseDir && process.env.MIGRATION_BASE) base = process.env.MIGRATION_BASE;
  if (!base && !baseDir && process.env.GITHUB_BASE_REF) {
    if (!/^[A-Za-z0-9._/-]+$/.test(process.env.GITHUB_BASE_REF)) return { error: UNRESOLVED };
    base = `origin/${process.env.GITHUB_BASE_REF}`;
  }
  return { migrations, base, baseDir };
}

function directoryBase(base) {
  try {
    const path = resolve(base);
    return statSync(path).isDirectory() ? path : null;
  } catch {
    return null;
  }
}

function git(args) {
  return spawnSync("git", ["--no-pager", ...args], {
    cwd: ROOT,
    encoding: "buffer",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function resolveCommit(rev) {
  if (rev.includes("\0") || rev.startsWith("-")) return null;
  const result = git(["rev-parse", "--verify", "--end-of-options", `${rev}^{commit}`]);
  if (result.status !== 0 || !result.stdout) return null;
  const sha = result.stdout.toString("utf8").trim();
  if (!/^[0-9a-f]{40}$/.test(sha) || /^0{40}$/.test(sha)) return null;
  return sha;
}

function materializeReleased(rev) {
  const sha = resolveCommit(rev);
  if (!sha) return null;
  const listing = git(["ls-tree", "-r", "--name-only", sha, "migrations"]);
  if (listing.status !== 0 || !listing.stdout) return null;
  const dir = mkdtempSync(join(tmpdir(), "migration-base-"));
  const paths = listing.stdout.toString("utf8").split("\n").map((line) => line.trim()).filter((line) => line.endsWith(".sql"));
  for (const path of paths) {
    if (!/^migrations\/[A-Za-z0-9._-]+\.sql$/.test(path)) {
      rmSync(dir, { recursive: true, force: true });
      return null;
    }
    const shown = git(["show", "--no-textconv", `${sha}:${path}`]);
    if (shown.status !== 0 || shown.stdout === null) {
      rmSync(dir, { recursive: true, force: true });
      return null;
    }
    writeFileSync(join(dir, path.slice("migrations/".length)), shown.stdout);
  }
  return dir;
}

function main() {
  const parsed = parseArgs(process.argv);
  if (parsed.error) {
    process.stderr.write(`${parsed.error}\n`);
    process.exit(1);
  }
  let releasedDirectory;
  let temporary;
  if (parsed.baseDir) {
    releasedDirectory = directoryBase(parsed.baseDir) ?? undefined;
    if (!releasedDirectory) {
      process.stderr.write(`${UNRESOLVED}\n`);
      process.exit(1);
    }
  } else if (parsed.base) {
    // Commit only. A directory named like the SHA must not satisfy --base.
    const materialized = materializeReleased(parsed.base);
    releasedDirectory = materialized ?? undefined;
    if (!releasedDirectory) {
      process.stderr.write(`${UNRESOLVED}\n`);
      process.exit(1);
    }
    temporary = materialized;
  } else if (process.env.GITHUB_ACTIONS === "true") {
    process.stderr.write(`${UNRESOLVED}\n`);
    process.exit(1);
  }
  try {
    const problems = checkMigrations(parsed.migrations, MIGRATION_SHA256, releasedDirectory);
    if (problems.length > 0) {
      process.stderr.write(`${problems.join("\n")}\n`);
      process.exit(1);
    }
    const count = sqlNames(parsed.migrations).length;
    const released = releasedDirectory ? sqlNames(releasedDirectory).length : null;
    const line = released === null
      ? `checked ${count} migration(s)`
      : `checked ${count} migration(s), ${released} released unchanged`;
    process.stdout.write(`${line}\n`);
  } finally {
    if (temporary) rmSync(temporary, { recursive: true, force: true });
  }
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) main();
