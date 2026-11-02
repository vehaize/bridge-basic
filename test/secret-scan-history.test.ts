/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const gitleaks = resolve(
  process.env.GITLEAKS_BIN ?? join(project, process.platform === "win32" ? "gitleaks.exe" : "gitleaks"),
);

function run(command: string, args: string[], cwd: string, env = process.env, status = 0): string {
  const result = spawnSync(command, args, { cwd, env, encoding: "utf8", timeout: 30_000 });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `${command} was interrupted`);
  assert.equal(result.status, status, `${command}: ${result.stderr}\n${result.stdout}`);
  return result.stdout.trim();
}

it("checks out complete history for the CI secret scan", () => {
  // This fails in Actions if fetch-depth: 0 is removed, even with a clean tip.
  assert.equal(run("git", ["rev-parse", "--is-shallow-repository"], project), "false");
});

it("limits the CI secret scan to the checked-out ref", () => {
  const workflow = readFileSync(join(project, ".github/workflows/ci.yml"), "utf8");
  const scan = workflow.split("gitleaks detect", 2)[1]?.split("\n", 1)[0] ?? "";
  assert.match(scan, /--log-opts="--full-history --diff-filter=tuxdb HEAD"/);
  assert.equal(scan.includes(" --all"), false);
});

it("detects an added-then-deleted synthetic secret only with full history", (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "gitleaks-history-"));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  // Keep author identity, signing settings, and hooks independent of the operator.
  const gitConfig = join(scratch, "gitconfig");
  writeFileSync(gitConfig, "");
  const env = { ...process.env, GIT_CONFIG_GLOBAL: gitConfig, GIT_CONFIG_NOSYSTEM: "1" };
  const source = join(scratch, "source");
  const shallow = join(scratch, "shallow");
  const full = join(scratch, "full");
  const git = (cwd: string, ...args: string[]) => run("git", args, cwd, env);
  const commit = (message: string) => git(
    source, "-c", "user.name=Secret scan fixture", "-c", "user.email=fixture@example.invalid",
    "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message,
  );
  const scan = (cwd: string, name: string, status: number) => {
    const report = join(scratch, `${name}.json`);
    run(gitleaks, [
      "detect", "--source", ".", "--redact", "--no-banner", "--exit-code", "1",
      "--report-format", "json", "--report-path", report,
    ], cwd, env, status);
    return JSON.parse(readFileSync(report, "utf8")) as {
      RuleID: string; File: string; Commit: string;
    }[];
  };

  git(scratch, "init", "--quiet", "--initial-branch=main", source);
  writeFileSync(join(source, "README.md"), "Synthetic secret scan history fixture.\n");
  git(source, "add", "README.md");
  commit("Clean baseline");
  assert.deepEqual(scan(source, "clean", 0), []);

  // Invented, never issued by GitHub. Assemble at runtime so the regression's
  // source code does not itself contain a token-shaped string in real history.
  const synthetic = ["ghp", "Ab3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zB5"].join("_");
  writeFileSync(join(source, "fixture.txt"), `token = "${synthetic}"\n`);
  git(source, "add", "fixture.txt");
  commit("Add synthetic secret");
  const secretCommit = git(source, "rev-parse", "HEAD");
  git(source, "rm", "--quiet", "fixture.txt");
  commit("Delete synthetic secret");

  // file:// forces Git's transport path: --depth is ignored for plain local paths.
  const sourceUrl = pathToFileURL(source).href;
  git(scratch, "clone", "--quiet", "--depth=1", sourceUrl, shallow);
  git(scratch, "clone", "--quiet", sourceUrl, full);
  assert.equal(git(shallow, "rev-parse", "--is-shallow-repository"), "true");
  assert.equal(git(full, "rev-parse", "--is-shallow-repository"), "false");
  assert.equal(git(shallow, "rev-list", "--count", "HEAD"), "1");
  assert.equal(git(full, "rev-list", "--count", "HEAD"), "3");
  assert.equal(git(shallow, "rev-parse", "HEAD"), git(full, "rev-parse", "HEAD"));
  for (const cwd of [source, shallow, full]) {
    assert.equal(existsSync(join(cwd, "fixture.txt")), false);
  }

  assert.deepEqual(scan(shallow, "shallow", 0), []);
  const findings = scan(full, "full", 1);
  assert.deepEqual(findings.map(({ RuleID, File, Commit }) => ({ RuleID, File, Commit })), [
    { RuleID: "github-pat", File: "fixture.txt", Commit: secretCommit },
  ]);
});
