/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * npm copies each dependency's funding field into lockfile v3 package
 * entries. The `fund` config only hides the install notice. This script
 * removes those fields from package-lock.json (and npm-shrinkwrap.json
 * when present). A second run changes nothing when the file is already
 * in that form. `--check` reads tracked files and fails when one of them
 * contains a funding URL or the blocked substring.
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const BLOCKED = String.fromCharCode(100, 111, 110, 97, 116, 101);
const FUNDING = "fund" + "ing";
const URL_IN_VALUE = /https?:\/\/[^\s"'<>\\]+/i;

export function stripFunding(lock) {
  let removed = 0;
  removed += stripEntry(lock);
  if (lock && typeof lock === "object") {
    removed += stripPackageMap(lock.packages);
    removed += stripLegacyDependencies(lock.dependencies);
  }
  return removed;
}

export function stripLockfile(path) {
  const raw = readFileSync(path, "utf8");
  const lock = JSON.parse(raw);
  const removed = stripFunding(lock);
  const next = `${JSON.stringify(lock, null, 2)}\n`;
  const changed = next !== raw;
  if (changed) writeFileSync(path, next);
  return { removed, changed };
}

export function checkText(file, text) {
  const failures = [];
  const lower = text.toLowerCase();
  let from = 0;
  while (from < lower.length) {
    const index = lower.indexOf(BLOCKED, from);
    if (index === -1) break;
    failures.push(`${file}:${lineOf(text, index)}: blocked substring ${BLOCKED}`);
    from = index + BLOCKED.length;
  }
  const urls = findFundingUrls(text);
  for (const hit of urls) {
    failures.push(`${file}:${lineOf(text, hit.index)}: funding URL`);
  }
  if (isLockfile(file)) {
    let lock;
    try {
      lock = JSON.parse(text);
    } catch {
      failures.push(`${file}:1: lockfile is not JSON`);
      return failures;
    }
    const fields = countFunding(lock);
    if (fields > urls.length) failures.push(`${file}:1: funding field`);
  }
  return failures;
}

export function checkRepository(root) {
  const failures = [];
  for (const file of trackedPaths(root)) {
    failures.push(...checkText(file, readFileSync(join(root, file), "utf8")));
  }
  return failures;
}

export function trackedPaths(root) {
  // Index only. CI extracts an untracked gitleaks binary before this check.
  const result = spawnSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = (result.stderr || "").trim() || "git ls-files failed";
    throw new Error(detail);
  }
  return result.stdout.split("\0").filter((file) => file.length > 0);
}

function stripPackageMap(packages) {
  if (!packages || typeof packages !== "object") return 0;
  let removed = 0;
  for (const entry of Object.values(packages)) removed += stripEntry(entry);
  return removed;
}

function stripLegacyDependencies(dependencies) {
  if (!dependencies || typeof dependencies !== "object") return 0;
  let removed = 0;
  for (const entry of Object.values(dependencies)) {
    if (!entry || typeof entry !== "object") continue;
    removed += stripEntry(entry);
    removed += stripLegacyDependencies(entry.dependencies);
  }
  return removed;
}

function stripEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return 0;
  if (!Object.prototype.hasOwnProperty.call(entry, FUNDING)) return 0;
  delete entry[FUNDING];
  return 1;
}

function countFunding(lock) {
  // Same walk as the strip, on a copy. A funding field with no URL still fails.
  return stripFunding(structuredClone(lock));
}

function isLockfile(file) {
  return file === "package-lock.json" || file === "npm-shrinkwrap.json" || file.endsWith("/package-lock.json") || file.endsWith("/npm-shrinkwrap.json");
}

export function findFundingUrls(text) {
  const hits = [];
  const pattern = /["']funding["']\s*:|(^|[\n\r,{])\s*funding\s*:/gi;
  for (const match of text.matchAll(pattern)) {
    const value = readValue(text, match.index + match[0].length);
    if (URL_IN_VALUE.test(value)) hits.push({ index: match.index });
  }
  return hits;
}

function readValue(text, index) {
  let cursor = index;
  while (cursor < text.length && isSpace(text[cursor])) cursor += 1;
  if (cursor >= text.length) return "";
  const mark = text[cursor];
  if (mark === '"' || mark === "'") return readQuoted(text, cursor, mark);
  if (mark === "{" || mark === "[") return readBalanced(text, cursor, mark === "{" ? "}" : "]");
  const slice = text.slice(cursor, cursor + 200);
  const end = slice.search(/[\n\r,]/);
  return end === -1 ? slice : slice.slice(0, end);
}

function readQuoted(text, start, quote) {
  let cursor = start + 1;
  while (cursor < text.length) {
    if (text[cursor] === "\\") {
      cursor += 2;
      continue;
    }
    if (text[cursor] === quote) return text.slice(start, cursor + 1);
    cursor += 1;
  }
  return text.slice(start);
}

function readBalanced(text, start, close) {
  const open = text[start];
  let depth = 0;
  const limit = Math.min(text.length, start + 4000);
  for (let cursor = start; cursor < limit; cursor += 1) {
    const mark = text[cursor];
    if (mark === open) depth += 1;
    else if (mark === close) {
      depth -= 1;
      if (depth === 0) return text.slice(start, cursor + 1);
    }
  }
  return text.slice(start, limit);
}

function isSpace(mark) {
  return mark === " " || mark === "\t" || mark === "\n" || mark === "\r";
}

function lineOf(text, index) {
  let line = 1;
  for (let cursor = 0; cursor < index; cursor += 1) {
    if (text.charCodeAt(cursor) === 10) line += 1;
  }
  return line;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  let check = false;
  let root = ROOT;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--check") {
      check = true;
      continue;
    }
    if (arg === "--root") {
      const value = argv[index + 1];
      if (!value) fail("usage: node scripts/lockfile-funding.mjs [--check] [--root <dir>]");
      root = resolve(value);
      index += 1;
      continue;
    }
    fail("usage: node scripts/lockfile-funding.mjs [--check] [--root <dir>]");
  }
  return { check, root };
}

function runStrip(root) {
  const names = ["package-lock.json", "npm-shrinkwrap.json"];
  let sawLock = false;
  for (const name of names) {
    const path = join(root, name);
    if (!existsSync(path)) continue;
    sawLock = true;
    const result = stripLockfile(path);
    const detail = result.changed
      ? `removed ${result.removed} funding field(s)`
      : "funding fields already absent";
    process.stdout.write(`${name}: ${detail}\n`);
  }
  if (!sawLock) fail("package-lock.json is missing");
}

function runCheck(root) {
  const failures = checkRepository(root);
  if (failures.length > 0) {
    process.stderr.write(`${failures.join("\n")}\n`);
    process.exit(1);
  }
  process.stdout.write(`checked ${trackedPaths(root).length} tracked file(s)\n`);
}

function main() {
  const { check, root } = parseArgs(process.argv.slice(2));
  if (check) runCheck(root);
  else runStrip(root);
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
