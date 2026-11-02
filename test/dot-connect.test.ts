/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { CONNECT_RESULT_TTL_SECONDS } from "../src/consent-idempotency.ts";
import { CLAIM_LEASE_MS, claimPollDelay, completeDotConnection, PENDING_CLAIM_SQL, type DotConnectDependencies, type DotAuthorizationRequest } from "../src/dot-connect.ts";
import { SqliteD1 } from "./d1-sqlite.ts";

const CLIENT = "https://chatgpt.com/oauth/client.json";
const REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const ORIGIN = "https://bridge.invalid";
const CODE = "s".repeat(43);
const HASH = createHash("sha256").update(CODE).digest("hex");
const NOW = Date.parse("2026-10-23T06:00:00.000Z");
const OWNER = "2026-10-22T00:00:00.000Z";
const EXPIRES = new Date(NOW + 600_000).toISOString();
const databases: SqliteD1[] = [];
const schema = readFileSync(new NodeURL("./fixtures/connect-code.sql", import.meta.url), "utf8");
function params(overrides: Record<string, string> = {}) {
  return new URLSearchParams({ connect_code: CODE, client_id: CLIENT, redirect_uri: REDIRECT,
    response_type: "code", code_challenge: "p".repeat(43), code_challenge_method: "S256",
    resource: `${ORIGIN}/mcp`, state: "synthetic-state", ...overrides });
}
function request(body: BodyInit = params().toString(), url = `${ORIGIN}/authorize`, headers: HeadersInit = { "Content-Type": "application/x-www-form-urlencoded" }) {
  return new Request(url, { method: "POST", headers, body });
}
function setup() {
  const d1 = new SqliteD1(); databases.push(d1); d1.sqlite.exec(schema);
  let now = NOW, dbNow = NOW;
  d1.sqlite.function("strftime", { varargs: true }, () => new Date(dbNow).toISOString());
  d1.sqlite.prepare("INSERT INTO owner_lock VALUES (1, ?, ?, 'first-boot')").run("synthetic-owner@example.invalid", OWNER);
  d1.sqlite.prepare("INSERT INTO connect_code VALUES (?, 'dot', ?, ?, NULL)").run(HASH, OWNER, EXPIRES);
  d1.sqlite.prepare(`INSERT INTO participant_credential
    (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at)
    VALUES ('old-dot', 'dot', 'oauth_grant', 'synthetic-old-hash', ?, ?)`).run(OWNER, OWNER);
  const calls = { parsed: [] as string[], completed: [] as Parameters<DotConnectDependencies["oauth"]["completeAuthorization"]>[0][] };
  const deps: DotConnectDependencies = { db: d1.binding(), resource: `${ORIGIN}/mcp`, now: () => now, oauth: {
    async parseAuthRequest(req) {
      calls.parsed.push(req.url);
      const p = new URL(req.url).searchParams;
      return { responseType: p.get("response_type")!, clientId: p.get("client_id")!, redirectUri: p.get("redirect_uri")!,
        scope: [], state: p.get("state") ?? "", codeChallenge: p.get("code_challenge")!, codeChallengeMethod: "S256",
        resource: p.get("resource")!, issuer: ORIGIN };
    },
    async completeAuthorization(options) {
      calls.completed.push(options);
      const url = new URL(REDIRECT); url.searchParams.set("code", "synthetic-authorization-code");
      url.searchParams.set("iss", ORIGIN); if (options.request.state) url.searchParams.set("state", options.request.state);
      return { redirectTo: url.href };
    },
  } };
  function snapshot() {
    return ["owner_lock", "bootstrap_secret_spend", "participant", "participant_credential", "connect_code", "item"]
      .map((table) => d1.sqlite.prepare(`SELECT * FROM ${table}`).all());
  }
  return { d1, deps, calls, snapshot, setNow: (value: number) => { now = value; }, setDbNow: (value: number) => { dbNow = value; } };
}
function expireSql(): string {
  const dir = mkdtempSync(join(tmpdir(), "connect-expire-"));
  const file = join(dir, "expire.sql");
  const script = fileURLToPath(new NodeURL("../scripts/connect-code.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [script, "expire", "--out", file], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const sql = readFileSync(file, "utf8");
  rmSync(dir, { recursive: true, force: true });
  assert.equal(sql.includes(PENDING_CLAIM_SQL), true);
  return sql;
}
function holdProvider(f: ReturnType<typeof setup>) {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let started: () => void = () => {};
  const saw = new Promise<void>((resolve) => { started = resolve; });
  let gated = false;
  const complete = f.deps.oauth.completeAuthorization;
  f.deps.oauth.completeAuthorization = async (options) => {
    if (!gated) {
      gated = true;
      started();
      await gate;
    }
    return complete(options);
  };
  return { saw, release: () => release() };
}
function pendingToken(f: ReturnType<typeof setup>): string {
  const used = f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at;
  assert.equal(typeof used, "string");
  assert.match(String(used), /"kind":"pending"/);
  assert.equal(Number.isNaN(Date.parse(String(used))), true);
  return String(used);
}
async function rejects(response: Response, status = 400, error = "connection_failed") {
  assert.equal(response.status, status);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(response.headers.get("Location"), null);
  assert.deepEqual(await response.json(), { error });
}
afterEach(() => { for (const db of databases.splice(0)) db.sqlite.close(); });

describe("unmounted Dot connect-code completion", () => {
  it("spends once, binds the current owner, and revokes only the previous Dot credential", async () => {
    const f = setup();
    f.d1.sqlite.prepare(`INSERT INTO participant_credential
      (id, participant, kind, token_sha256, owner_claimed_at, created_at)
      VALUES ('grok', 'grok_bot', 'bearer', 'synthetic-grok-hash', ?, ?)`).run(OWNER, OWNER);
    const result = await completeDotConnection(request(), f.deps);
    assert.equal(result.status, 303);
    assert.equal(result.headers.get("Cache-Control"), "no-store");
    assert.equal(await result.text(), "");
    assert.equal(f.calls.completed.length, 1);
    const options = f.calls.completed[0];
    assert.equal(options.userId, "dot"); assert.deepEqual(options.metadata, {});
    assert.equal(options.revokeExistingGrants, false);
    assert.deepEqual(Object.keys(options.props), ["credential_id"]);
    assert.ok(f.calls.parsed.every((url) => !url.includes(CODE) && !url.includes("connect_code")));
    const row = f.d1.sqlite.prepare("SELECT * FROM participant_credential WHERE id = ?").get(options.props.credential_id);
    assert.equal(row?.owner_claimed_at, OWNER); assert.equal(row?.connect_code_sha256, HASH);
    const used = JSON.parse(String(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at)) as {
      kind?: string; at?: string; credential_id?: string; challenge?: string; location?: string;
    };
    assert.equal(used.kind, "spent");
    assert.equal(used.at, new Date(NOW).toISOString());
    assert.equal(used.credential_id, options.props.credential_id);
    assert.equal(used.challenge, "p".repeat(43));
    assert.equal(used.location, result.headers.get("Location"));
    assert.equal(f.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential WHERE id = 'old-dot'").get()?.revoked_at, new Date(NOW).toISOString());
    assert.equal(f.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential WHERE id = 'grok'").get()?.revoked_at, null);
    assert.ok(f.d1.sessions.every((constraint) => constraint === "first-primary"));
    const before = f.snapshot();
    const location = result.headers.get("Location");
    const replay = await completeDotConnection(request(), f.deps);
    assert.equal(replay.status, 303);
    assert.equal(replay.headers.get("Location"), location);
    assert.deepEqual(f.snapshot(), before); assert.equal(f.calls.completed.length, 1);
  });
  it("does not replay a cached redirect for a different challenge", async () => {
    const f = setup();
    assert.equal((await completeDotConnection(request(), f.deps)).status, 303);
    await rejects(await completeDotConnection(request(params({ code_challenge: "q".repeat(43) }).toString()), f.deps));
    assert.equal(f.calls.completed.length, 1);
    assert.notEqual(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, null);
  });
  for (const [name, overrides] of [
    ["wrong client", { client_id: "https://other.invalid/client.json" }],
    ["normalized client alias", { client_id: "https://chatgpt.com:443/oauth/client.json" }],
    ["wrong redirect", { redirect_uri: `${REDIRECT}/extra` }],
    ["wrong audience", { resource: "https://other.invalid/mcp" }],
    ["implicit response", { response_type: "token" }],
    ["plain PKCE", { code_challenge_method: "plain" }],
    ["missing PKCE", { code_challenge: "" }],
    ["malformed code", { connect_code: "invalid" }],
    ["forged owner", { owner_claimed_at: OWNER }],
    ["forged participant", { userId: "dot" }],
  ] as [string, Record<string, string>][]) {
    it(`rejects ${name} before provider or storage access`, async () => {
      const f = setup(), before = f.snapshot();
      await rejects(await completeDotConnection(request(params(overrides).toString()), f.deps));
      assert.equal(f.d1.sessions.length, 0); assert.equal(f.calls.parsed.length, 0);
      assert.deepEqual(f.snapshot(), before);
    });
  }
  it("rejects duplicate fields and codes in URLs", async () => {
    const f = setup(), before = f.snapshot();
    const duplicate = params(); duplicate.append("client_id", CLIENT);
    await rejects(await completeDotConnection(request(duplicate.toString()), f.deps));
    await rejects(await completeDotConnection(request(params().toString(), `${ORIGIN}/authorize?connect_code=${CODE}`), f.deps));
    assert.equal(f.d1.sessions.length, 0); assert.deepEqual(f.snapshot(), before);
  });
  it("bounds form parsing and checks method, content type and UTF-8", async () => {
    const f = setup();
    await rejects(await completeDotConnection(new Request(`${ORIGIN}/authorize`), f.deps), 405, "method_not_allowed");
    await rejects(await completeDotConnection(request("{}", undefined, { "Content-Type": "application/json" }), f.deps), 415, "unsupported_media_type");
    await rejects(await completeDotConnection(request("x".repeat(16 * 1024 + 1)), f.deps), 413, "body_too_large");
    await rejects(await completeDotConnection(request(new Uint8Array([0xff])), f.deps));
    assert.equal(f.d1.sessions.length, 0);
  });
  for (const [name, sql] of [
    ["unknown", "DELETE FROM connect_code"],
    ["spent", "UPDATE connect_code SET used_at = 'synthetic-spent'"],
    ["expired", `UPDATE connect_code SET expires_at = '${new Date(NOW - 1).toISOString()}'`],
    ["exact expiry", `UPDATE connect_code SET expires_at = '${new Date(NOW).toISOString()}'`],
    ["stale owner", "UPDATE connect_code SET owner_claimed_at = 'previous-owner'"],
    ["reset owner", "UPDATE owner_lock SET claimed_at = 'new-owner'"],
    ["missing owner", "DELETE FROM owner_lock"],
  ]) {
    it(`rejects ${name} before provider access`, async () => {
      const f = setup(); f.d1.sqlite.exec(sql); const before = f.snapshot();
      const started = Date.now();
      await rejects(await completeDotConnection(request(), f.deps));
      if (name === "spent") assert.ok(Date.now() - started < 500);
      assert.equal(f.calls.parsed.length, 0); assert.deepEqual(f.snapshot(), before);
    });
  }
  it("admits just before expiry", async () => {
    const f = setup(); f.setNow(NOW + 599_999); f.setDbNow(NOW + 599_999);
    assert.equal((await completeDotConnection(request(), f.deps)).status, 303);
  });
  it("rolls back revocation if the code expires between transaction statements", async () => {
    const f = setup(); let reads = 0;
    f.d1.sqlite.function("strftime", { varargs: true }, () => new Date(++reads <= 4 ? NOW : NOW + 600_000).toISOString());
    await rejects(await completeDotConnection(request(), f.deps));
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n, 1);
    assert.equal(f.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential").get()?.revoked_at, null);
    assert.match(String(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at), /"kind":"pending"/);
  });
  it("rolls back insertion if the code expires before the final spend", async () => {
    const f = setup(); let reads = 0;
    f.d1.sqlite.function("strftime", { varargs: true }, () => new Date(++reads <= 5 ? NOW : NOW + 600_000).toISOString());
    await rejects(await completeDotConnection(request(), f.deps));
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n, 1);
    assert.equal(f.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential").get()?.revoked_at, null);
    assert.match(String(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at), /"kind":"pending"/);
  });
  for (const name of ["expiry", "owner reset", "code spent"]) {
    it(`rejects ${name} during provider completion without changing credentials`, async () => {
      const f = setup(), complete = f.deps.oauth.completeAuthorization;
      f.deps.oauth.completeAuthorization = async (options) => {
        const result = await complete(options);
        if (name === "expiry") f.setNow(NOW + 600_000);
        if (name === "owner reset") f.d1.sqlite.exec("UPDATE owner_lock SET claimed_at = 'new-owner'");
        if (name === "code spent") f.d1.sqlite.exec("UPDATE connect_code SET used_at = 'another-attempt'");
        return result;
      };
      await rejects(await completeDotConnection(request(), f.deps));
      assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n, 1);
      assert.equal(f.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential").get()?.revoked_at, null);
    });
  }
  it("returns one redirect when two submits race on the claim", async () => {
    const f = setup();
    f.d1.holdWritesUntil(2);
    const responses = await Promise.all([completeDotConnection(request(), f.deps), completeDotConnection(request(), f.deps)]);
    assert.deepEqual(responses.map((response) => response.status), [303, 303]);
    assert.equal(responses[0]?.headers.get("Location"), responses[1]?.headers.get("Location"));
    assert.ok(responses[0]?.headers.get("Location"));
    assert.equal(f.calls.completed.length, 1);
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").get()?.n, 1);
  });
  for (const point of ["parse", "complete", "read", "write", "constraint"]) {
    it(`maps ${point} failure safely and preserves D1 state`, async () => {
      const f = setup(), before = f.snapshot();
      const error = new Error(`synthetic-sensitive ${CODE}`);
      if (point === "parse") f.deps.oauth.parseAuthRequest = async () => { throw error; };
      if (point === "complete") f.deps.oauth.completeAuthorization = async () => { throw error; };
      if (point === "read") f.d1.failRead(error);
      if (point === "write") f.d1.failNextWrite(error);
      if (point === "constraint") f.d1.sqlite.exec("CREATE TRIGGER refuse_insert BEFORE INSERT ON participant_credential BEGIN SELECT RAISE(ABORT, 'synthetic-sensitive'); END");
      await rejects(await completeDotConnection(request(), f.deps), 500, "internal_error");
      assert.deepEqual(f.snapshot(), before);
    });
  }
  it("rejects a malformed provider redirect without spending the code", async () => {
    const f = setup(), before = f.snapshot();
    f.deps.oauth.completeAuthorization = async () => ({ redirectTo: "https://other.invalid/?code=synthetic" });
    await rejects(await completeDotConnection(request(), f.deps), 500, "internal_error");
    assert.deepEqual(f.snapshot(), before);
    assert.equal(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, null);
  });
  it("rejects misbound provider context and invalid server configuration", async () => {
    const f = setup(), before = f.snapshot();
    f.deps.oauth.parseAuthRequest = async () => ({ clientId: "wrong" }) as DotAuthorizationRequest;
    await rejects(await completeDotConnection(request(), f.deps), 500, "internal_error");
    f.deps.resource = "http://bridge.invalid/mcp";
    await rejects(await completeDotConnection(request(), f.deps), 500, "internal_error");
    assert.deepEqual(f.snapshot(), before); assert.equal(f.calls.completed.length, 0);
  });
  it("replays the redirect bound to the committed credential after a lost commit", async () => {
    const f = setup();
    const db = f.deps.db;
    f.deps.db = {
      withSession(constraint?: unknown) {
        const session = db.withSession(constraint as "first-primary");
        return {
          prepare: (sql: string) => session.prepare(sql),
          batch: async (statements: readonly { sql?: string }[]) => {
            const result = await session.batch(statements as unknown as D1PreparedStatement[]);
            if (statements.some((statement) => (statement.sql ?? "").includes("SET used_at = ?3"))) {
              throw new Error("synthetic-lost-commit");
            }
            return result;
          },
        };
      },
    } as unknown as D1Database;
    const lost = await completeDotConnection(request(), f.deps);
    await rejects(lost, 500, "internal_error");
    assert.equal(f.calls.completed.length, 1);
    const credential = f.calls.completed[0]?.props.credential_id;
    assert.equal(f.d1.sqlite.prepare("SELECT id FROM participant_credential WHERE revoked_at IS NULL AND id = ?").get(credential)?.id, credential);
    const used = JSON.parse(String(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at)) as {
      credential_id?: string; location?: string;
    };
    assert.equal(used.credential_id, credential);
    const replay = await completeDotConnection(request(), f.deps);
    assert.equal(replay.status, 303);
    assert.equal(replay.headers.get("Location"), used.location);
    assert.equal(f.calls.completed.length, 1);
  });
  it("fails closed when the replay read fails", async () => {
    const f = setup();
    const first = await completeDotConnection(request(), f.deps);
    assert.equal(first.status, 303);
    const before = f.snapshot();
    f.d1.failRead(new Error("synthetic-read"));
    await rejects(await completeDotConnection(request(), f.deps), 500, "internal_error");
    assert.equal(f.calls.completed.length, 1);
    assert.deepEqual(f.snapshot(), before);
  });
  it("clears a disconnected claim so the next submit does not wait on it", async () => {
    const f = setup();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let started: () => void = () => {};
    const saw = new Promise<void>((resolve) => { started = resolve; });
    let gated = false;
    const complete = f.deps.oauth.completeAuthorization;
    f.deps.oauth.completeAuthorization = async (options) => {
      if (!gated) {
        gated = true;
        started();
        await gate;
      }
      return complete(options);
    };
    const controller = new AbortController();
    const abandoned = completeDotConnection(new Request(`${ORIGIN}/authorize`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params().toString(), signal: controller.signal,
    }), f.deps);
    await saw;
    assert.equal(typeof f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, "string");
    controller.abort();
    const deadline = Date.now() + 1_000;
    let used: unknown = "pending";
    while (Date.now() < deadline) {
      used = f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at;
      if (used === null) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(used, null);
    const startedAt = Date.now();
    const second = await completeDotConnection(request(), f.deps);
    assert.ok(Date.now() - startedAt < 1_000);
    assert.equal(second.status, 303);
    release();
    assert.equal((await abandoned).status, 500);
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential WHERE revoked_at IS NULL").get()?.n, 1);
  });
  it("replaces an expired claim without waiting out the redirect cache", async () => {
    const f = setup();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let started: () => void = () => {};
    const saw = new Promise<void>((resolve) => { started = resolve; });
    let gated = false;
    const complete = f.deps.oauth.completeAuthorization;
    f.deps.oauth.completeAuthorization = async (options) => {
      if (!gated) {
        gated = true;
        started();
        await gate;
      }
      return complete(options);
    };
    const abandoned = completeDotConnection(request(), f.deps);
    await saw;
    f.setNow(NOW + CLAIM_LEASE_MS);
    const startedAt = Date.now();
    const second = await completeDotConnection(request(), f.deps);
    assert.ok(Date.now() - startedAt < 1_000);
    assert.equal(second.status, 303);
    release();
    const loser = await abandoned;
    assert.equal(loser.status, 303);
    assert.equal(loser.headers.get("Location"), second.headers.get("Location"));
    const winner = f.calls.completed[0]?.props.credential_id;
    const displaced = f.calls.completed[1]?.props.credential_id;
    assert.equal(f.d1.sqlite.prepare("SELECT id FROM participant_credential WHERE id = ? AND revoked_at IS NULL").get(winner)?.id, winner);
    assert.equal(f.d1.sqlite.prepare("SELECT id FROM participant_credential WHERE id = ?").get(displaced), undefined);
  });
  it("bounds claim polling to 25 reads of each store across the 10s lease", () => {
    const delays = [0, 1, 2, 3, 4, 5, 6].map((attempt) => claimPollDelay(attempt));
    assert.deepEqual(delays, [25, 50, 100, 200, 400, 500, 500]);
    let elapsed = 0;
    let polls = 0;
    let attempt = 0;
    for (;;) {
      polls += 1;
      if (elapsed >= CLAIM_LEASE_MS) break;
      elapsed += claimPollDelay(attempt);
      attempt += 1;
    }
    const flatPolls = Math.ceil(CLAIM_LEASE_MS / 25);
    assert.equal(polls, 25);
    assert.ok(polls * 2 <= 50);
    assert.ok(polls < flatPolls);
  });
  it("does not poll every 25ms while a claim is in flight", async () => {
    const f = setup();
    const held = holdProvider(f);
    const first = completeDotConnection(request(), f.deps);
    await held.saw;
    const replayReads = () => f.d1.prepared.filter((sql) => sql.startsWith("SELECT c.used_at AS used_at, p.id AS credential_id")).length;
    const baseline = replayReads();
    const second = completeDotConnection(request(), f.deps);
    await new Promise((resolve) => setTimeout(resolve, 400));
    const reads = replayReads() - baseline;
    held.release();
    await Promise.all([first, second]);
    assert.ok(reads >= 3, String(reads));
    assert.ok(reads <= 9, String(reads));
  });
  it("does not commit a claim expired while the provider is still running", async () => {
    const f = setup();
    const held = holdProvider(f);
    const pending = completeDotConnection(request(), f.deps);
    await held.saw;
    const token = pendingToken(f);
    f.d1.sqlite.exec(expireSql());
    held.release();
    await rejects(await pending);
    assert.equal(pendingToken(f), token);
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n, 1);
    assert.equal(f.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential").get()?.revoked_at, null);
  });
  it("refuses a lapsed claim after expire and does not spend the code", async () => {
    const f = setup();
    const held = holdProvider(f);
    const abandoned = completeDotConnection(request(), f.deps);
    await held.saw;
    const token = pendingToken(f);
    f.setNow(NOW + CLAIM_LEASE_MS);
    f.setDbNow(NOW + CLAIM_LEASE_MS);
    f.d1.sqlite.exec(expireSql());
    const started = Date.now();
    await rejects(await completeDotConnection(request(), f.deps));
    assert.ok(Date.now() - started < 500);
    assert.equal(pendingToken(f), token);
    assert.equal(f.calls.completed.length, 0);
    held.release();
    await rejects(await abandoned);
    assert.equal(pendingToken(f), token);
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n, 1);
    assert.equal(f.d1.sqlite.prepare("SELECT revoked_at FROM participant_credential").get()?.revoked_at, null);
    assert.equal(f.calls.completed.length, 1);
  });
  it("returns the winner's redirect after a displaced claim finishes", async () => {
    const f = setup();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let started: () => void = () => {};
    const saw = new Promise<void>((resolve) => { started = resolve; });
    const complete = f.deps.oauth.completeAuthorization;
    let turn = 0;
    f.deps.oauth.completeAuthorization = async (options) => {
      turn += 1;
      if (turn === 1) {
        started();
        await gate;
        const url = new URL(REDIRECT);
        url.searchParams.set("code", "displaced-authorization-code");
        url.searchParams.set("iss", ORIGIN);
        url.searchParams.set("state", options.request.state);
        return { redirectTo: url.href };
      }
      return complete(options);
    };
    const displaced = completeDotConnection(request(), f.deps);
    await saw;
    const displacedCredential = JSON.parse(pendingToken(f)).credential_id as string;
    f.setNow(NOW + CLAIM_LEASE_MS);
    f.setDbNow(NOW + CLAIM_LEASE_MS);
    const winner = await completeDotConnection(request(), f.deps);
    assert.equal(winner.status, 303);
    const winnerLocation = winner.headers.get("Location");
    assert.ok(winnerLocation);
    const winnerCredential = f.calls.completed[0]?.props.credential_id;
    assert.notEqual(winnerCredential, displacedCredential);
    release();
    const loser = await displaced;
    assert.equal(loser.status, 303);
    assert.equal(loser.headers.get("Location"), winnerLocation);
    const startedAt = Date.now();
    const duplicate = await completeDotConnection(request(), f.deps);
    assert.ok(Date.now() - startedAt < 1_000);
    assert.equal(duplicate.status, 303);
    assert.equal(duplicate.headers.get("Location"), winnerLocation);
    assert.equal(f.calls.completed.length, 1);
    assert.equal(f.d1.sqlite.prepare("SELECT id FROM participant_credential WHERE revoked_at IS NULL").get()?.id, winnerCredential);
  });
  it("refuses a replay when the state differs", async () => {
    const f = setup();
    const first = await completeDotConnection(request(), f.deps);
    assert.equal(first.status, 303);
    const before = f.d1.sqlite.prepare("SELECT used_at, expires_at FROM connect_code").get();
    await rejects(await completeDotConnection(request(params({ state: "other-state" }).toString()), f.deps));
    assert.equal(f.calls.completed.length, 1);
    assert.deepEqual(f.d1.sqlite.prepare("SELECT used_at, expires_at FROM connect_code").get(), before);
    const used = JSON.parse(String(before?.used_at)) as { location?: string };
    assert.equal(used.location, first.headers.get("Location"));
  });
  it("refuses a replay when the active credential is revoked", async () => {
    const f = setup();
    const first = await completeDotConnection(request(), f.deps);
    assert.equal(first.status, 303);
    const stored = String(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at);
    const used = JSON.parse(stored) as { credential_id?: string; location?: string };
    assert.equal(used.location, first.headers.get("Location"));
    assert.equal(typeof used.credential_id, "string");
    f.d1.sqlite.prepare("UPDATE participant_credential SET revoked_at = ? WHERE id = ?").run(new Date(NOW).toISOString(), String(used.credential_id));
    await rejects(await completeDotConnection(request(), f.deps));
    assert.equal(f.calls.completed.length, 1);
    assert.equal(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, stored);
    assert.equal(f.d1.sqlite.prepare("SELECT count(*) AS n FROM participant_credential").get()?.n, 2);
  });
  it("replays a spent redirect inside 120s and clears it after the window", async () => {
    const f = setup();
    const first = await completeDotConnection(request(), f.deps);
    assert.equal(first.status, 303);
    const location = first.headers.get("Location");
    const expires = f.d1.sqlite.prepare("SELECT expires_at FROM connect_code").get()?.expires_at;
    const credentialId = f.calls.completed[0]?.props.credential_id;
    f.setNow(NOW + CONNECT_RESULT_TTL_SECONDS * 1000);
    const edge = await completeDotConnection(request(), f.deps);
    assert.equal(edge.status, 303);
    assert.equal(edge.headers.get("Location"), location);
    const open = JSON.parse(String(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at)) as { location?: string };
    assert.equal(open.location, location);
    f.setNow(NOW + CONNECT_RESULT_TTL_SECONDS * 1000 + 1);
    await rejects(await completeDotConnection(request(), f.deps));
    const marker = JSON.stringify({
      v: 1, kind: "spent", at: new Date(NOW).toISOString(), credential_id: credentialId, challenge: "p".repeat(43),
    });
    assert.equal(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, marker);
    assert.equal(f.d1.sqlite.prepare("SELECT expires_at FROM connect_code").get()?.expires_at, expires);
    assert.equal(f.calls.completed.length, 1);
    await rejects(await completeDotConnection(request(), f.deps));
    assert.equal(f.d1.sqlite.prepare("SELECT used_at FROM connect_code").get()?.used_at, marker);
    assert.equal(f.d1.sqlite.prepare("SELECT expires_at FROM connect_code").get()?.expires_at, expires);
  });
});
