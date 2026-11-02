/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, it, mock } from "node:test";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";
import { PENDING_CLAIM_SQL } from "../src/dot-connect.ts";
import { CHATGPT_CLIENT_ID, CHATGPT_REDIRECT, type BridgeEnv } from "../src/oauth-routes.ts";
import { routeRequest } from "../src/router.ts";
import { SqliteD1 } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts/connect-code.mjs");
const CODE = /^[A-Za-z0-9_-]{43}$/;
const ORIGIN = "https://bridge.example";
const RESOURCE = `${ORIGIN}/mcp`;
const EMAIL = "synthetic-owner@example.invalid";
const OWNER = "2026-10-22T00:00:00.000Z";
const CIMD = {
  client_id: CHATGPT_CLIENT_ID,
  client_name: "ChatGPT",
  redirect_uris: [CHATGPT_REDIRECT],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
};

interface Stored {
  value: string;
}

class MemoryKv {
  readonly records = new Map<string, Stored>();
  writes = 0;

  async get(key: string, options?: { type?: string }): Promise<unknown> {
    const row = this.records.get(key);
    if (!row) return null;
    return options?.type === "json" ? JSON.parse(row.value) as unknown : row.value;
  }

  async put(key: string, value: string): Promise<void> {
    this.writes += 1;
    this.records.set(key, { value });
  }

  async delete(key: string): Promise<void> {
    this.records.delete(key);
  }

  async list(): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor: string }> {
    return { keys: [...this.records.keys()].map((name) => ({ name })), list_complete: true, cursor: "" };
  }
}

const directories: string[] = [];
const databases: SqliteD1[] = [];
const logs: string[] = [];

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: ROOT, encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function directory(): string {
  const created = mkdtempSync(join(tmpdir(), "connect-code-"));
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

function pkce(code: string): string {
  let challenge = code;
  while (challenge === code || !CODE.test(challenge)) {
    challenge = createHash("sha256").update(randomBytes(32)).digest("base64url");
  }
  return challenge;
}

function binding(d1: SqliteD1, kv: MemoryKv): BridgeEnv {
  return { DB: d1.binding(), OAUTH_KV: kv as unknown as KVNamespace, BRIDGE_ORIGIN: ORIGIN, OWNER_EMAIL: EMAIL, ...permissiveRateLimits() };
}

function silence(): void {
  mock.method(globalThis, "fetch", async (input: unknown) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== CHATGPT_CLIENT_ID) throw new Error(`unexpected fetch ${url}`);
    return Response.json(CIMD, { headers: { "Cache-Control": "no-store" } });
  });
  mock.method(console, "log", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
  mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
}

async function authorize(env: BridgeEnv, code: string): Promise<Response> {
  const challenge = pkce(code);
  const body = new URLSearchParams({
    connect_code: code,
    client_id: CHATGPT_CLIENT_ID,
    redirect_uri: CHATGPT_REDIRECT,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
    state: "synthetic-state",
  });
  return routeRequest(new Request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  }), env);
}

afterEach(() => {
  for (const db of databases.splice(0)) db.sqlite.close();
  for (const created of directories.splice(0)) rmSync(created, { recursive: true, force: true });
  logs.length = 0;
  mock.restoreAll();
});

type Fold =
  | { kind: "string"; value: string }
  | { kind: "number"; value: number }
  | { kind: "list"; value: Fold[] };

/** Fold string constants so a joined or repeated GLOB cannot hide past D1's limit. */
function sqlTexts(file: string): { sql: string[]; claim: string | undefined } {
  const text = readFileSync(file, "utf8");
  if (file.endsWith(".sql")) return { sql: [text], claim: undefined };
  const kind = file.endsWith(".ts") || file.endsWith(".mts") ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, kind);
  if ("parseDiagnostics" in source && Array.isArray(source.parseDiagnostics) && source.parseDiagnostics.length > 0) {
    assert.fail(`${relative(ROOT, file)} did not parse`);
  }
  const scopes: Map<string, Fold | undefined>[] = [];
  const sql: string[] = [];
  let claim: string | undefined;
  const lookup = (name: string): Fold | undefined => {
    for (let index = scopes.length - 1; index >= 0; index -= 1) {
      const scope = scopes[index];
      if (scope?.has(name)) return scope.get(name);
    }
    return undefined;
  };
  const record = (value: string): void => {
    if (/\b(?:GLOB|LIKE)\b/i.test(value)) sql.push(value);
  };
  const fold = (node: ts.Node): Fold | undefined => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return { kind: "string", value: node.text };
    if (ts.isNumericLiteral(node)) return { kind: "number", value: Number(node.text.replaceAll("_", "")) };
    if (ts.isIdentifier(node)) return lookup(node.text);
    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) return fold(node.expression);
    if (ts.isTemplateExpression(node)) {
      let value = node.head.text;
      for (const span of node.templateSpans) {
        const part = fold(span.expression);
        if (part?.kind !== "string") return undefined;
        value += part.value + span.literal.text;
      }
      return { kind: "string", value };
    }
    if (ts.isArrayLiteralExpression(node)) {
      const value: Fold[] = [];
      for (const element of node.elements) {
        if (!ts.isExpression(element)) return undefined;
        const item = fold(element);
        if (!item) return undefined;
        value.push(item);
      }
      return { kind: "list", value };
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = fold(node.left);
      const right = fold(node.right);
      if (left?.kind !== "string" || right?.kind !== "string") return undefined;
      return { kind: "string", value: left.value + right.value };
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const receiver = fold(node.expression.expression);
      const method = node.expression.name.text;
      const argument = node.arguments[0];
      if (node.arguments.length !== 1 || argument === undefined) return undefined;
      if (method === "repeat" && receiver?.kind === "string") {
        const count = fold(argument);
        if (count?.kind !== "number" || !Number.isInteger(count.value) || count.value < 0 || count.value > 10_000) return undefined;
        return { kind: "string", value: receiver.value.repeat(count.value) };
      }
      if (method === "join" && receiver?.kind === "list") {
        const separator = fold(argument);
        if (separator?.kind !== "string") return undefined;
        const parts: string[] = [];
        for (const item of receiver.value) {
          if (item.kind !== "string") return undefined;
          parts.push(item.value);
        }
        return { kind: "string", value: parts.join(separator.value) };
      }
    }
    return undefined;
  };
  const absorb = (node: ts.Node): void => {
    if ((ts.isVariableDeclaration(node) || ts.isPropertyDeclaration(node)) && node.initializer) {
      const value = fold(node.initializer);
      if (/\b(?:GLOB|LIKE)\b/i.test(node.initializer.getText(source)) && value?.kind !== "string") {
        const name = ts.isIdentifier(node.name) ? node.name.text : "binding";
        assert.fail(`${relative(ROOT, file)} did not fold ${name}`);
      }
      if (value?.kind === "string") record(value.value);
      if (ts.isIdentifier(node.name)) {
        scopes.at(-1)?.set(node.name.text, value);
        if (node.name.text === "PENDING_CLAIM_SQL" && value?.kind === "string") claim = value.value;
      }
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateExpression(node)
      || ts.isCallExpression(node) || ts.isBinaryExpression(node)) {
      const value = fold(node);
      if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateExpression(node))
        && /\b(?:GLOB|LIKE)\b/i.test(node.getText(source)) && value?.kind !== "string") {
        assert.fail(`${relative(ROOT, file)} did not fold a GLOB or LIKE string`);
      }
      if (value?.kind === "string") record(value.value);
    }
  };
  const walk = (node: ts.Node): void => {
    const scoped = ts.isSourceFile(node) || ts.isBlock(node) || ts.isFunctionLike(node) || ts.isModuleBlock(node);
    if (scoped) scopes.push(new Map());
    else absorb(node);
    ts.forEachChild(node, walk);
    if (scoped) scopes.pop();
  };
  walk(source);
  return { sql, claim };
}

function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...sourceFiles(path));
    else if (/\.(?:ts|mts|cts|mjs|cjs|js|sql)$/.test(entry.name)) found.push(path);
  }
  return found;
}

describe("Dot connect-code command", () => {
  it("issues and expires Claude codes without changing Dot codes", () => {
    const dir = directory(), d1 = database();
    for (const participant of ["dot", "claude"]) {
      const file = join(dir, `${participant}.sql`);
      const issued = run(["issue", "--participant", participant, "--out", file]);
      assert.equal(issued.status, 0);
      const code = issued.stdout.trim(), sql = readFileSync(file, "utf8");
      assert.match(code, CODE);
      assert.equal(sql.includes(code), false);
      assert.equal(issued.stderr.includes(code), false);
      applyFile(d1.sqlite, sql);
      const hash = createHash("sha256").update(code).digest("hex");
      assert.equal(d1.sqlite.prepare("SELECT participant FROM connect_code WHERE code_sha256 = ?").get(hash)?.participant, participant);
    }
    const dot = d1.sqlite.prepare("SELECT * FROM connect_code WHERE participant = 'dot'").get();
    const path = join(dir, "claude-expire.sql");
    assert.equal(run(["expire", "--out", path, "--participant", "claude"]).status, 0);
    applyFile(d1.sqlite, readFileSync(path, "utf8"));
    assert.deepEqual(d1.sqlite.prepare("SELECT * FROM connect_code WHERE participant = 'dot'").get(), dot);
    assert.equal(d1.sqlite.prepare("SELECT expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now') AS expired FROM connect_code WHERE participant = 'claude'").get()?.expired, 1);
    assert.equal(d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n, 0);
    for (const participant of ["grok_bot", "unknown", "claude' OR 1=1"]) {
      const invalid = run(["issue", "--participant", participant, "--out", join(dir, "invalid.sql")]);
      assert.equal(invalid.status, 1);
      assert.equal(invalid.stdout, "");
    }
  });

  it("prints a code once, stores only its hash, and /authorize accepts that hash", async () => {
    silence();
    const dir = directory();
    const file = join(dir, "issue.sql");
    const issued = run(["issue", "--out", file]);
    assert.equal(issued.status, 0);
    const code = issued.stdout.trim();
    assert.match(code, CODE);
    assert.equal(issued.stdout, `${code}\n`);
    const hash = createHash("sha256").update(code).digest("hex");
    const sql = readFileSync(file, "utf8");
    assert.equal(sql.includes(hash), true);
    assert.equal(sql.includes(code), false);
    assert.equal(issued.stderr.includes(code), false);
    assert.equal(issued.stderr.includes(hash), false);
    assert.match(issued.stderr, /does not apply it/);
    assert.match(sql, /\+10 minutes/);
    assert.equal(statSync(file).mode & 0o777, 0o600);

    const d1 = database();
    applyFile(d1.sqlite, sql);
    const row = d1.sqlite.prepare("SELECT participant, owner_claimed_at, expires_at, used_at FROM connect_code WHERE code_sha256 = ?").get(hash) as {
      participant: string;
      owner_claimed_at: string;
      expires_at: string;
      used_at: string | null;
    };
    assert.equal(row.participant, "dot");
    assert.equal(row.owner_claimed_at, OWNER);
    assert.equal(row.used_at, null);
    const window = d1.sqlite.prepare(`SELECT ?1 > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+9 minutes') AS after_nine,
      ?1 <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+10 minutes') AS within_ten`).get(row.expires_at) as {
      after_nine: number;
      within_ten: number;
    };
    assert.equal(window.after_nine, 1);
    assert.equal(window.within_ten, 1);

    const kv = new MemoryKv();
    const consented = await authorize(binding(d1, kv), code);
    const failure = consented.status === 303 ? "" : await consented.text();
    assert.equal(consented.status, 303, failure);
    assert.equal(failure.includes(code), false);
    assert.equal(d1.sqlite.prepare("SELECT used_at FROM connect_code WHERE code_sha256 = ?").get(hash)?.used_at == null, false);
    assert.equal(logs.join("\n").includes(code), false);
    assert.equal(logs.join("\n").includes(hash), false);

    const again = run(["issue", "--out", file]);
    assert.notEqual(again.status, 0);
    assert.equal(again.stdout, "");
    assert.equal(again.stderr.includes(code), false);
    assert.equal(statSync(file).mode & 0o777, 0o600);
  });

  it("rolls back an issue when the owner lock is missing and expires unused codes", async () => {
    const dir = directory();
    const issuePath = join(dir, "missing-lock.sql");
    const issued = run(["issue", "--out", issuePath]);
    assert.equal(issued.status, 0);
    const code = issued.stdout.trim();
    const hash = createHash("sha256").update(code).digest("hex");
    const bare = new DatabaseSync(":memory:");
    try {
      for (const file of ["0001_owner_lock.sql", "0002_item_lifecycle.sql", "0003_participant_credentials.sql", "0004_connect_code.sql"]) {
        bare.exec(readFileSync(join(ROOT, "migrations", file), "utf8"));
      }
      assert.throws(() => applyFile(bare, readFileSync(issuePath, "utf8")));
      assert.equal(bare.prepare("SELECT COUNT(*) AS count FROM connect_code").get()?.count, 0);
    } finally {
      bare.close();
    }

    silence();
    const d1 = database();
    applyFile(d1.sqlite, readFileSync(issuePath, "utf8"));
    const expirePath = join(dir, "expire.sql");
    const expired = run(["expire", "--out", expirePath]);
    assert.equal(expired.status, 0);
    assert.equal(expired.stdout, "");
    const expireSql = readFileSync(expirePath, "utf8");
    assert.equal(expireSql.includes(code), false);
    assert.equal(expireSql.includes(hash), false);
    assert.equal(/\b[a-f0-9]{64}\b/.test(expireSql), false);
    assert.equal(expired.stderr.includes(code), false);
    assert.equal(expired.stderr.includes(hash), false);
    assert.match(expired.stderr, /does not apply it/);
    assert.equal(statSync(expirePath).mode & 0o777, 0o600);
    applyFile(d1.sqlite, expireSql);
    const spent = d1.sqlite.prepare("SELECT expires_at, used_at FROM connect_code WHERE code_sha256 = ?").get(hash) as {
      expires_at: string;
      used_at: string | null;
    };
    assert.equal(spent.used_at, null);
    assert.equal(d1.sqlite.prepare("SELECT ?1 > strftime('%Y-%m-%dT%H:%M:%fZ', 'now') AS live").get(spent.expires_at)?.live, 0);
    const kv = new MemoryKv();
    const refused = await authorize(binding(d1, kv), code);
    assert.equal(refused.status, 400);
    assert.equal((await refused.text()).includes(code), false);
    assert.equal(kv.writes, 0);
    assert.equal(d1.sqlite.prepare("SELECT used_at FROM connect_code WHERE code_sha256 = ?").get(hash)?.used_at, null);
    assert.equal(logs.join("\n").includes(code), false);
  });

  it("expires a pending claim and leaves a spent timestamp unused", () => {
    const dir = directory();
    const expirePath = join(dir, "expire.sql");
    const expired = run(["expire", "--out", expirePath]);
    assert.equal(expired.status, 0);
    const expireSql = readFileSync(expirePath, "utf8");
    assert.equal(expireSql.includes(PENDING_CLAIM_SQL), true);
    assert.match(expireSql, /used_at IS NULL OR/);
    const pending = JSON.stringify({
      v: 1, kind: "pending", credential_id: "credential_01234567-89ab-4def-ab01-23456789abcd", until: 1_700_000_000_000,
    });
    const spentAt = "2026-10-23T06:00:00.000Z";
    const future = "2999-01-01T00:00:00.000Z";
    const rows = [
      ["unused", null, true],
      ["pending", pending, true],
      ["spent", spentAt, false],
      ["record", JSON.stringify({
        v: 1, kind: "spent", at: "2999-01-01T00:00:00.000Z",
        credential_id: "credential_01234567-89ab-4def-ab01-23456789abcd",
        challenge: "p".repeat(43),
        location: "https://chatgpt.com/connector_platform_oauth_redirect?code=synthetic&state=synthetic-state",
      }), false],
      ["synthetic", "synthetic-spent", false],
      ["extra", pending.replace(/}$/, `,"x":1}`), false],
      ["reordered", JSON.stringify({ kind: "pending", v: 1, until: 1_700_000_000_000, credential_id: "credential_01234567-89ab-4def-ab01-23456789abcd" }), false],
      ["upper", pending.replace("credential_01234567", "CREDENTIAL_01234567"), false],
    ] as const;
    const d1 = database();
    for (const [name, used] of rows) {
      d1.sqlite.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, ?, ?)").run(name.padEnd(64, "0"), OWNER, future, used);
    }
    applyFile(d1.sqlite, expireSql);
    for (const [name, used, shouldExpire] of rows) {
      const row = d1.sqlite.prepare("SELECT expires_at, used_at FROM connect_code WHERE code_sha256 = ?").get(name.padEnd(64, "0")) as {
        expires_at: string;
        used_at: string | null;
      };
      assert.equal(row.used_at, used, name);
      const live = d1.sqlite.prepare("SELECT ?1 > strftime('%Y-%m-%dT%H:%M:%fZ', 'now') AS live").get(row.expires_at)?.live;
      assert.equal(live, shouldExpire ? 0 : 1, name);
      if (!shouldExpire) assert.equal(row.expires_at, future, name);
    }
  });

  it("clears a spent redirect older than 120s and keeps the spend marker", () => {
    const dir = directory();
    const expirePath = join(dir, "expire.sql");
    const expired = run(["expire", "--out", expirePath]);
    assert.equal(expired.status, 0);
    const expireSql = readFileSync(expirePath, "utf8");
    const location = "https://chatgpt.com/connector_platform_oauth_redirect?code=synthetic&state=synthetic-state";
    const credentialId = "credential_01234567-89ab-4def-ab01-23456789abcd";
    const challenge = "p".repeat(43);
    const spent = (at: string, withLocation: boolean) => JSON.stringify({
      v: 1, kind: "spent", at, credential_id: credentialId, challenge, ...(withLocation ? { location } : {}),
    });
    const d1 = database();
    const freshAt = d1.sqlite.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now') AS at").get()?.at;
    assert.equal(typeof freshAt, "string");
    const future = "2999-01-01T00:00:00.000Z";
    const staleAt = "2000-01-01T00:00:00.000Z";
    const rows = [
      ["fresh", spent(String(freshAt), true)],
      ["stale", spent(staleAt, true)],
      ["odd", JSON.stringify({ v: 1, kind: "spent", at: staleAt, location })],
    ] as const;
    for (const [name, used] of rows) {
      d1.sqlite.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, ?, ?)").run(name.padEnd(64, "0"), OWNER, future, used);
    }
    applyFile(d1.sqlite, expireSql);
    const kept = d1.sqlite.prepare("SELECT expires_at, used_at FROM connect_code WHERE code_sha256 = ?").get("fresh".padEnd(64, "0")) as {
      expires_at: string; used_at: string;
    };
    assert.equal(kept.expires_at, future);
    assert.equal(kept.used_at, spent(String(freshAt), true));
    const cleared = d1.sqlite.prepare("SELECT expires_at, used_at FROM connect_code WHERE code_sha256 = ?").get("stale".padEnd(64, "0")) as {
      expires_at: string; used_at: string;
    };
    assert.equal(cleared.expires_at, future);
    assert.equal(cleared.used_at, spent(staleAt, false));
    const odd = d1.sqlite.prepare("SELECT expires_at, used_at FROM connect_code WHERE code_sha256 = ?").get("odd".padEnd(64, "0")) as {
      expires_at: string; used_at: string;
    };
    assert.equal(odd.expires_at, future);
    assert.equal(odd.used_at, rows[2][1]);
    applyFile(d1.sqlite, expireSql);
    assert.equal(d1.sqlite.prepare("SELECT used_at FROM connect_code WHERE code_sha256 = ?").get("stale".padEnd(64, "0"))?.used_at, spent(staleAt, false));
    assert.equal(d1.sqlite.prepare("SELECT expires_at FROM connect_code WHERE code_sha256 = ?").get("stale".padEnd(64, "0"))?.expires_at, future);
  });

  it("rejects malformed arguments and a code-shaped argument without echoing it", () => {
    const secret = "c".repeat(43);
    const hash = "d".repeat(64);
    const cases = [
      [],
      ["issue"],
      ["issue", "--out"],
      ["revoke", "--out", "revoke.sql"],
      ["expire", "--file", "expire.sql"],
      ["issue", "--out", "one.sql", "two.sql"],
      ["issue", "--code", secret, "--out", "ignored.sql"],
      ["expire", "--code", secret],
      ["issue", "--out", hash],
      ["expire", "--out", secret],
    ];
    for (const args of cases) {
      const result = run(args);
      assert.notEqual(result.status, 0, args.join(" "));
      assert.equal(result.stdout, "", args.join(" "));
      assert.equal(result.stderr.includes(secret), false, args.join(" "));
      assert.equal(result.stderr.includes(hash), false, args.join(" "));
      assert.match(result.stderr, /usage:|refusing a code or hash argument/, args.join(" "));
    }
    const source = readFileSync(SCRIPT, "utf8");
    assert.equal(source.includes("child_process"), false);
    assert.equal(source.includes("wrangler deploy"), false);
    assert.match(source, /getRandomValues/);
    assert.doesNotMatch(source, /Math\.random/);
  });

  it("rejects a GLOB or LIKE literal longer than 50 bytes", () => {
    const hits: { file: string; pattern: string }[] = [];
    for (const file of [...sourceFiles(join(ROOT, "src")), ...sourceFiles(join(ROOT, "scripts"))]) {
      const rel = relative(ROOT, file).replaceAll("\\", "/");
      const { sql, claim } = sqlTexts(file);
      if (claim !== undefined) assert.equal(claim, PENDING_CLAIM_SQL, rel);
      for (const statement of sql) {
        for (const match of statement.matchAll(/\b(?:GLOB|LIKE)\s+'([^']*)'/gi)) {
          hits.push({ file: rel, pattern: match[1] ?? "" });
        }
      }
    }
    const seen = new Set(hits.filter((hit) => hit.pattern === "*[^0-9a-f-]*").map((hit) => hit.file));
    assert.equal(seen.has("src/dot-connect.ts"), true);
    assert.equal(seen.has("scripts/connect-code.mjs"), true);
    for (const hit of hits) {
      const bytes = Buffer.byteLength(hit.pattern);
      assert.ok(bytes <= 50, `${hit.file} pattern is ${bytes} bytes: ${hit.pattern}`);
    }
  });
});
