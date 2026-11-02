/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { it } from "node:test";
import { fileURLToPath } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(project, "scripts/dco-signoff.sh");

type GitEnv = NodeJS.ProcessEnv;

type Repo = {
  root: string;
  env: GitEnv;
  revision: number;
};

type Check = {
  status: number | null;
  stdout: string;
  stderr: string;
};

function git(cwd: string, env: GitEnv, args: string[], status = 0): string {
  const result = spawnSync("git", args, { cwd, env, encoding: "utf8" });
  assert.ifError(result.error);
  assert.equal(result.status, status, `git ${args.join(" ")}: ${result.stderr}\n${result.stdout}`);
  return result.stdout.trim();
}

function createRepo(t: { after(fn: () => void): void }): Repo {
  const scratch = mkdtempSync(join(tmpdir(), "dco-signoff-"));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const root = join(scratch, "repo");
  const gitConfig = join(scratch, "gitconfig");
  const hooks = join(scratch, "hooks");
  writeFileSync(gitConfig, "");
  mkdirSync(hooks);
  const env: GitEnv = { ...process.env, GIT_CONFIG_GLOBAL: gitConfig, GIT_CONFIG_NOSYSTEM: "1" };
  git(scratch, env, ["init", "--quiet", "--initial-branch=main", root]);
  git(root, env, ["config", "commit.gpgsign", "false"]);
  git(root, env, ["config", "core.hooksPath", hooks]);
  return { root, env, revision: 0 };
}

function commit(repo: Repo, name: string, email: string, message: string, file = "note.txt"): string {
  repo.revision += 1;
  writeFileSync(join(repo.root, file), `${repo.revision}\n`);
  const messageFile = join(dirname(repo.root), "commit-message.txt");
  writeFileSync(messageFile, message);
  git(repo.root, repo.env, ["add", file]);
  git(repo.root, repo.env, [
    "-c", `user.name=${name}`,
    "-c", `user.email=${email}`,
    "-c", "commit.gpgsign=false",
    "commit", "--cleanup=verbatim", "--quiet", "-F", messageFile,
  ]);
  return git(repo.root, repo.env, ["rev-parse", "HEAD"]);
}

function check(repo: Repo, base: string, head: string): Check {
  const result = spawnSync("bash", [script], {
    cwd: repo.root,
    env: { ...repo.env, BASE_SHA: base, HEAD_SHA: head, PR_NUMBER: "", BASE_REF: "" },
    encoding: "utf8",
  });
  assert.ifError(result.error);
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function signoff(name: string, email: string): string {
  return `Signed-off-by: ${name} <${email}>`;
}

const author = { name: "Cursor Agent", email: "cursoragent@cursor.com" };

function messageWith(lines: string[]): string {
  return ["Record the change.", "", ...lines].join("\n");
}

it("accepts a sign-off in the final trailer block", (t) => {
  const repo = createRepo(t);
  const base = commit(repo, author.name, author.email, "base");
  const head = commit(repo, author.name, author.email, messageWith([
    signoff(author.name, author.email),
    "Co-authored-by: Example Dev <dev@example.invalid>",
  ]));
  const result = check(repo, base, head);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /checked 1 commit\(s\)/);
});

it("accepts a sign-off before a blank line and a Co-authored-by block", (t) => {
  const repo = createRepo(t);
  const base = commit(repo, author.name, author.email, "base");
  const head = commit(repo, author.name, author.email, messageWith([
    signoff(author.name, author.email),
    "",
    "Co-authored-by: Example Dev <dev@example.invalid>",
  ]));
  const stored = git(repo.root, repo.env, ["log", "-1", "--format=%B"]);
  assert.match(stored, /Signed-off-by: Cursor Agent <cursoragent@cursor\.com>\n\nCo-authored-by:/);
  const result = check(repo, base, head);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /checked 1 commit\(s\)/);
});

it("accepts a long message whose sign-off is near the beginning", (t) => {
  const repo = createRepo(t);
  const base = commit(repo, author.name, author.email, "base");
  const line = signoff(author.name, author.email);
  const padding = "padding\n".repeat(55_000);
  const head = commit(repo, author.name, author.email, [line, "", padding, line].join("\n"));
  const stored = git(repo.root, repo.env, ["log", "-1", "--format=%B"]);
  assert.ok(stored.length > 400_000, `message was only ${stored.length} bytes`);
  assert.equal(stored.startsWith(`${line}\n`), true);
  assert.equal(stored.endsWith(line), true);
  const result = check(repo, base, head);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /checked 1 commit\(s\)/);
});

it("rejects a commit with no sign-off", (t) => {
  const repo = createRepo(t);
  const base = commit(repo, author.name, author.email, "base");
  const head = commit(repo, author.name, author.email, messageWith(["No sign-off on this commit."]));
  const result = check(repo, base, head);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /missing Signed-off-by trailer:/);
});

it("rejects a sign-off whose name or email differs from the author", (t) => {
  const repo = createRepo(t);
  const base = commit(repo, author.name, author.email, "base");
  const otherName = commit(repo, author.name, author.email, messageWith([
    signoff("Other Person", author.email),
  ]));
  const nameResult = check(repo, base, otherName);
  assert.equal(nameResult.status, 1, nameResult.stdout + nameResult.stderr);
  assert.match(nameResult.stdout, /missing Signed-off-by trailer:/);

  const otherEmail = commit(repo, author.name, author.email, messageWith([
    signoff(author.name, "other@example.com"),
  ]));
  const emailResult = check(repo, otherName, otherEmail);
  assert.equal(emailResult.status, 1, emailResult.stdout + emailResult.stderr);
  assert.match(emailResult.stdout, /missing Signed-off-by trailer:/);
});

it("rejects a sign-off that is only part of a longer line", (t) => {
  const repo = createRepo(t);
  const base = commit(repo, author.name, author.email, "base");
  const line = signoff(author.name, author.email);
  const head = commit(repo, author.name, author.email, messageWith([
    `Noted ${line} earlier.`,
    `${line} thanks`,
  ]));
  const result = check(repo, base, head);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /missing Signed-off-by trailer:/);
});

it("rejects a malformed sign-off that matches the author but not the line shape", (t) => {
  const repo = createRepo(t);
  const name = "Pat Example";
  const email = "not-an-email";
  const base = commit(repo, name, email, "base");
  const head = commit(repo, name, email, messageWith([signoff(name, email)]));
  const result = check(repo, base, head);
  assert.equal(result.status, 1, result.stdout + result.stderr);
});

it("matches the author name as text, not as a pattern", (t) => {
  const repo = createRepo(t);
  const name = "A.*";
  const email = "a@b.c";
  const base = commit(repo, name, email, "base");
  const exact = commit(repo, name, email, messageWith([signoff(name, email)]));
  const exactResult = check(repo, base, exact);
  assert.equal(exactResult.status, 0, exactResult.stdout + exactResult.stderr);

  const similar = commit(repo, name, email, messageWith([signoff("AXXX", email)]));
  const similarResult = check(repo, exact, similar);
  assert.equal(similarResult.status, 1, similarResult.stdout + similarResult.stderr);
});

it("keeps the last trailer block rule for merge commits", (t) => {
  const repo = createRepo(t);
  commit(repo, "Root", "root@example.com", "root");
  git(repo.root, repo.env, ["checkout", "--quiet", "-b", "side"]);
  commit(
    repo,
    "Side Author",
    "side@example.com",
    ["Side change.", "", signoff("Side Author", "side@example.com")].join("\n"),
    "side.txt",
  );
  git(repo.root, repo.env, ["checkout", "--quiet", "main"]);
  const mainTip = commit(repo, "Main Author", "main@example.com", messageWith([
    signoff("Main Author", "main@example.com"),
  ]));

  const separated = [
    "Merge branch 'side'",
    "",
    signoff("Main Author", "main@example.com"),
    "",
    "Co-authored-by: Side Author <side@example.com>",
  ].join("\n");
  git(repo.root, repo.env, [
    "-c", "user.name=Main Author",
    "-c", "user.email=main@example.com",
    "-c", "commit.gpgsign=false",
    "merge", "--no-ff", "--cleanup=verbatim", "-m", separated, "side",
  ]);
  const separatedStored = git(repo.root, repo.env, ["log", "-1", "--format=%B"]);
  assert.match(separatedStored, /Signed-off-by: Main Author <main@example\.com>\n\nCo-authored-by:/);
  const separatedResult = check(repo, mainTip, git(repo.root, repo.env, ["rev-parse", "HEAD"]));
  assert.equal(separatedResult.status, 1, separatedResult.stdout + separatedResult.stderr);
  assert.match(separatedResult.stdout, /missing Signed-off-by trailer: .*Merge branch 'side'/);
  assert.equal(separatedResult.stdout.includes("Side change."), false);

  git(repo.root, repo.env, ["reset", "--hard", "--quiet", mainTip]);
  const other = ["Merge branch 'side'", "", signoff("Other Person", "other@example.com")].join("\n");
  git(repo.root, repo.env, [
    "-c", "user.name=Main Author",
    "-c", "user.email=main@example.com",
    "-c", "commit.gpgsign=false",
    "merge", "--no-ff", "--cleanup=verbatim", "-m", other, "side",
  ]);
  const otherResult = check(repo, mainTip, git(repo.root, repo.env, ["rev-parse", "HEAD"]));
  assert.equal(otherResult.status, 0, otherResult.stdout + otherResult.stderr);
  assert.match(otherResult.stdout, /checked 2 commit\(s\)/);
});

it("keeps the Signed-off-by job name and the commit id checks", () => {
  const workflow = readFileSync(join(project, ".github/workflows/dco.yml"), "utf8");
  const source = readFileSync(script, "utf8");
  assert.equal(workflow.match(/^ {4}name: Signed-off-by$/gm)?.length, 1);
  assert.equal(workflow.includes("interpret-trailers"), false);
  assert.match(workflow, /bash scripts\/dco-signoff\.sh/);
  assert.match(source, /base SHA is not a commit id/);
  assert.match(source, /head SHA is not a commit id/);
  assert.match(source, /pull request commits are not in this checkout/);
});
