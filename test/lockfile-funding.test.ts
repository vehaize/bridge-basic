/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  checkRepository,
  checkText,
  stripFunding,
  stripLockfile,
} from "../scripts/lockfile-funding.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts/lockfile-funding.mjs");
const FIELD = "fund" + "ing";
const BLOCKED = String.fromCharCode(100, 111, 110, 97, 116, 101);

function funding(url: string, withType = false): Record<string, unknown> {
  const value = withType ? { type: "github", url } : { url };
  return { version: "1.0.0", [FIELD]: value };
}

describe("lockfile funding metadata", () => {
  it("removes funding fields and leaves the file unchanged on the next run", () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        "": { name: "sample" },
        "node_modules/a": funding("https://example.invalid/a"),
        "node_modules/b": funding("https://example.invalid/b", true),
        "node_modules/c": { version: "1.0.0", [FIELD]: "https://example.invalid/c" },
      },
      dependencies: {
        a: {
          version: "1.0.0",
          [FIELD]: "https://example.invalid/a",
          dependencies: {
            nested: funding("https://example.invalid/nested"),
          },
        },
      },
    };
    assert.equal(stripFunding(lock), 5);
    assert.equal(stripFunding(lock), 0);
    assert.equal(JSON.stringify(lock).includes(FIELD), false);
    assert.equal(lock.packages[""].name, "sample");
    assert.equal(lock.packages["node_modules/a"].version, "1.0.0");

    const dir = mkdtempSync(join(tmpdir(), "lockfile-funding-"));
    try {
      const path = join(dir, "package-lock.json");
      const original = {
        lockfileVersion: 3,
        packages: {
          "node_modules/a": funding("https://example.invalid/a"),
        },
      };
      writeFileSync(path, `${JSON.stringify(original, null, 2)}\n`);
      const first = stripLockfile(path);
      const once = readFileSync(path, "utf8");
      const second = stripLockfile(path);
      assert.equal(first.changed, true);
      assert.equal(first.removed, 1);
      assert.equal(second.changed, false);
      assert.equal(second.removed, 0);
      assert.equal(readFileSync(path, "utf8"), once);
      assert.equal(once.includes(FIELD), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a funding URL and the blocked substring, including inside a lockfile", () => {
    const plain = "The funding field is metadata.\n";
    assert.deepEqual(checkText("note.txt", plain), []);

    const blocked = `${BLOCKED.slice(0, 1).toUpperCase()}${BLOCKED.slice(1)}`;
    const word = checkText("note.txt", `see ${blocked} please\n`);
    assert.equal(word.length, 1);
    assert.match(word[0], /^note.txt:1: blocked substring /);
    assert.equal(word[0].endsWith(BLOCKED), true);

    const key = `"${FIELD}"`;
    const objectUrl = `{\n  ${key}: {\n    "url": "https://example.invalid/support"\n  }\n}\n`;
    const objectHit = checkText("README.md", objectUrl);
    assert.equal(objectHit.length, 1);
    assert.match(objectHit[0], /^README.md:2: funding URL$/);

    const stringUrl = `{\n  ${key}: "https://example.invalid/support"\n}\n`;
    assert.match(checkText("other.json", stringUrl)[0], /funding URL$/);

    const listUrl = `{\n  ${key}: ["https://example.invalid/support"]\n}\n`;
    assert.match(checkText("other.json", listUrl)[0], /funding URL$/);

    const bare = `{\n  "packages": {\n    "node_modules/a": {\n      "version": "1.0.0",\n      ${key}: { "type": "individual" }\n    }\n  }\n}\n`;
    const bareHit = checkText("package-lock.json", bare);
    assert.deepEqual(bareHit, ["package-lock.json:1: funding field"]);
  });

  it("fails the check command when a tracked lockfile carries an appeal URL", (t) => {
    const scratch = mkdtempSync(join(tmpdir(), "funding-check-"));
    t.after(() => rmSync(scratch, { recursive: true, force: true }));
    const root = join(scratch, "repo");
    const gitConfig = join(scratch, "gitconfig");
    writeFileSync(gitConfig, "");
    mkdirSync(root);
    const env = { ...process.env, GIT_CONFIG_GLOBAL: gitConfig, GIT_CONFIG_NOSYSTEM: "1" };
    const git = (args: string[]) => {
      const result = spawnSync("git", args, { cwd: root, env, encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
    };
    git(["init", "--quiet", "--initial-branch=main"]);
    git(["config", "commit.gpgsign", "false"]);
    git(["config", "user.name", "Funding check"]);
    git(["config", "user.email", "funding-check@example.invalid"]);
    const url = `https://eslint.org/${BLOCKED}`;
    const body = `{\n  "name": "sample",\n  "lockfileVersion": 3,\n  "packages": {\n    "node_modules/eslint": {\n      "version": "1.0.0",\n      "${FIELD}": { "url": "${url}" }\n    }\n  }\n}\n`;
    writeFileSync(join(root, "package-lock.json"), body);
    git(["add", "package-lock.json"]);
    git(["commit", "--quiet", "-m", "fixture"]);
    const failed = spawnSync(process.execPath, [SCRIPT, "--check", "--root", root], { encoding: "utf8" });
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /package-lock\.json:\d+: blocked substring /);
    assert.match(failed.stderr, /package-lock\.json:\d+: funding URL/);
    assert.equal(failed.stderr.includes(BLOCKED), true);
    const stripped = spawnSync(process.execPath, [SCRIPT, "--root", root], { encoding: "utf8" });
    assert.equal(stripped.status, 0, stripped.stderr);
    const again = spawnSync(process.execPath, [SCRIPT, "--check", "--root", root], { encoding: "utf8" });
    assert.equal(again.status, 0, again.stderr);
    assert.equal(readFileSync(join(root, "package-lock.json"), "utf8").includes(BLOCKED), false);
  });

  it("accepts this repository and the check command", () => {
    const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as {
      packages: Record<string, Record<string, unknown>>;
    };
    for (const entry of Object.values(lock.packages)) {
      assert.equal(Object.prototype.hasOwnProperty.call(entry, FIELD), false);
    }
    assert.equal(lock.packages[""].hasInstallScript, true);
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
      scripts: { postinstall: string };
    };
    assert.equal(pkg.scripts.postinstall, "node scripts/lockfile-funding.mjs");
    const ci = readFileSync(join(ROOT, ".github/workflows/ci.yml"), "utf8");
    assert.match(ci, /node scripts\/lockfile-funding\.mjs --check/);
    assert.deepEqual(checkRepository(ROOT), []);
    const result = spawnSync(process.execPath, [SCRIPT, "--check"], { cwd: ROOT, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^checked \d+ tracked file\(s\)\n$/);
  });
});
