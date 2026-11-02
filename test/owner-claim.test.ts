/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { after, before, beforeEach, describe, it, mock } from "node:test";
import { fileURLToPath } from "node:url";
import type { BridgeEnv } from "../src/oauth-routes.ts";
import { routeRequest } from "../src/router.ts";
import { SqliteD1 } from "./d1-sqlite.ts";
import { permissiveRateLimits } from "./permissive-limits.ts";

const CLAIM_URL = "https://bridge.invalid/owner/claim";
const OWNER = " Ada@Example.com ";

const doubles: SqliteD1[] = [];
const compares: Array<[Buffer, Buffer]> = [];
const logLines: string[] = [];

interface Vars {
  OWNER_EMAIL?: string;
  BOOTSTRAP_SECRET?: string;
}

interface Sent {
  status: number;
  body: unknown;
}

function newSecret(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString(
    "base64url",
  );
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function install(vars: Vars = {}): { d1: SqliteD1; env: BridgeEnv } {
  const d1 = new SqliteD1();
  doubles.push(d1);
  return {
    d1,
    env: { DB: d1.binding(), BRIDGE_ORIGIN: "https://bridge.invalid", OWNER_EMAIL: OWNER, BOOTSTRAP_SECRET: newSecret(), ...vars, ...permissiveRateLimits() },
  };
}

function withSecret(env: BridgeEnv): HeadersInit {
  return { "Bootstrap-Secret": env.BOOTSTRAP_SECRET ?? "" };
}

function rows(d1: SqliteD1): { owner: unknown[]; spend: unknown[] } {
  const all = (sql: string) =>
    d1.sqlite
      .prepare(sql)
      .all()
      .map((row) => ({ ...row }));
  return {
    owner: all("SELECT * FROM owner_lock"),
    spend: all("SELECT * FROM bootstrap_secret_spend ORDER BY secret_sha256"),
  };
}

const NOTHING_WRITTEN = { owner: [], spend: [] };

// Sends one request and checks that neither the response nor any log line
// carries the owner email, a secret, a secret hash, or the request body.
async function send(
  env: BridgeEnv,
  init: {
    headers?: HeadersInit;
    body?: string | ReadableStream<Uint8Array>;
    url?: string;
    method?: string;
  } = {},
): Promise<Sent> {
  const request = new Request(init.url ?? CLAIM_URL, {
    method: init.method ?? "POST",
    headers: init.headers,
    body: init.body,
    duplex: "half",
  } as RequestInit);
  const presented = request.headers.get("Bootstrap-Secret");
  const firstLine = logLines.length;
  const response = await routeRequest(request, env);
  const text = await response.text();

  const secrets = [env.BOOTSTRAP_SECRET, presented].filter(
    (value): value is string => typeof value === "string" && value.trim() !== "",
  );
  const sensitive = [
    env.OWNER_EMAIL,
    env.OWNER_EMAIL?.trim(),
    env.OWNER_EMAIL?.trim().toLowerCase(),
    typeof init.body === "string" ? init.body : undefined,
    ...secrets,
    ...secrets.map((secret) => sha256(secret).toString("hex")),
  ].filter((value): value is string => typeof value === "string" && value.trim() !== "");
  for (const value of sensitive) {
    assert.equal(text.includes(value), false, "response carries a sensitive value");
    for (const line of logLines) {
      assert.equal(line.includes(value), false, "log carries a sensitive value");
    }
  }

  const body: unknown = JSON.parse(text);
  if (request.method === "POST" && new URL(request.url).pathname === "/owner/claim") {
    const error = (body as { error?: string }).error;
    const outcome = logLines
      .slice(firstLine)
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .find(
        (fields) =>
          fields.message === "owner claim" &&
          fields.status === response.status &&
          fields.error === error,
      );
    assert.notEqual(outcome, undefined, "claim outcome is logged");
  }
  return { status: response.status, body };
}

function expectRejected(sent: Sent, status: number, error: string): void {
  assert.deepEqual(sent, { status, body: { error } });
}

// Starts both claims together and holds their writes until both are ready, so
// both read empty tables before either batch runs.
async function race(d1: SqliteD1, first: BridgeEnv, second: BridgeEnv): Promise<Sent[]> {
  d1.holdWritesUntil(2);
  const sent = await Promise.all([
    send(first, { headers: withSecret(first) }),
    send(second, { headers: withSecret(second) }),
  ]);
  return sent.sort((a, b) => a.status - b.status);
}

describe("POST /owner/claim", () => {
  before(() => {
    // Workers provide crypto.subtle.timingSafeEqual. Node does not, so the
    // tests supply it and record what the Worker compares.
    Object.defineProperty(crypto.subtle, "timingSafeEqual", {
      configurable: true,
      value: (a: ArrayBuffer | ArrayBufferView, b: ArrayBuffer | ArrayBufferView) => {
        const bytes = (value: ArrayBuffer | ArrayBufferView) =>
          Buffer.from(
            ArrayBuffer.isView(value)
              ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
              : new Uint8Array(value),
          );
        const left = bytes(a);
        const right = bytes(b);
        compares.push([left, right]);
        if (left.length !== right.length) {
          throw new TypeError("Input buffers must have the same byte length");
        }
        return timingSafeEqual(left, right);
      },
    });
    const capture = (...args: unknown[]) => {
      logLines.push(args.map(String).join(" "));
    };
    mock.method(console, "log", capture);
    mock.method(console, "error", capture);
  });

  after(() => {
    Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
    mock.restoreAll();
  });

  beforeEach(() => {
    compares.length = 0;
  });

  it("requires the Bootstrap-Secret header before owner configuration or storage", async () => {
    const { d1, env } = install({ OWNER_EMAIL: undefined, BOOTSTRAP_SECRET: undefined });
    expectRejected(await send(env), 401, "bootstrap_secret_required");
    expectRejected(
      await send(env, { headers: { "Bootstrap-Secret": "" } }),
      401,
      "bootstrap_secret_required",
    );
    expectRejected(
      await send(env, { body: '{"owner_email":"mallory@example.com"}' }),
      401,
      "bootstrap_secret_required",
    );
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
    assert.equal(compares.length, 0);
    assert.deepEqual(d1.sessions, []);
  });

  it("refuses non-BRIDGE_ORIGIN claims without spending quota or the secret, then allows the canonical origin", async () => {
    const { d1, env } = install();
    let charged = 0;
    const guarded = { ...env, ...permissiveRateLimits(async () => { charged += 1; return { success: true }; }) };
    for (const origin of ["https://alternate.invalid", "http://bridge.invalid", "https://bridge.invalid:8443"]) {
      const sites: Record<string, string>[] = [{}, { Origin: "https://bridge.invalid", "Sec-Fetch-Site": "same-origin" }, { Origin: origin, "Sec-Fetch-Site": "same-origin" }];
      for (const site of sites) {
        assert.deepEqual(await send(guarded, {
          url: `${origin}/owner/claim`,
          headers: { "Bootstrap-Secret": guarded.BOOTSTRAP_SECRET ?? "", ...site },
        }), { status: 404, body: { ok: false, error: "not_found" } });
      }
    }
    assert.equal(charged, 0);
    assert.equal(compares.length, 0);
    assert.deepEqual(d1.sessions, []);
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);

    assert.deepEqual(await send(guarded, { headers: withSecret(guarded) }), {
      status: 201, body: { locked: true },
    });
    assert.equal(charged, 1);
    assert.equal(rows(d1).owner.length, 1);
    assert.equal(rows(d1).spend.length, 1);
  });

  it("fails closed before quota or secret checks when BRIDGE_ORIGIN is missing or invalid", async () => {
    const { d1, env } = install();
    let charged = 0;
    for (const origin of [undefined, "", "not-an-origin", "http://bridge.invalid", "https://bridge.invalid/path", "https://bridge.invalid:8443"]) {
      const guarded = { ...env, BRIDGE_ORIGIN: origin, ...permissiveRateLimits(async () => { charged += 1; return { success: true }; }) };
      expectRejected(await send(guarded, { headers: withSecret(guarded) }), 500, "internal_error");
    }
    assert.equal(charged, 0);
    assert.equal(compares.length, 0);
    assert.deepEqual(d1.sessions, []);
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
  });

  it("returns no-store origin refusals before requiring a secret without quota, comparison, or storage", async () => {
    const { d1, env } = install();
    let charged = 0;
    for (const [url, origin, status, body] of [
      ["https://alternate.invalid/owner/claim", env.BRIDGE_ORIGIN, 404, { ok: false, error: "not_found" }],
      [CLAIM_URL, undefined, 500, { error: "internal_error" }],
      [CLAIM_URL, "not-an-origin", 500, { error: "internal_error" }],
    ] as const) {
      const guarded = { ...env, BRIDGE_ORIGIN: origin, ...permissiveRateLimits(async () => { charged += 1; return { success: true }; }) };
      const response = await routeRequest(new Request(url, { method: "POST" }), guarded);
      assert.equal(response.status, status);
      assert.deepEqual(await response.json(), body);
      assert.equal(response.headers.get("Cache-Control"), "no-store");
    }
    assert.equal(charged, 0);
    assert.equal(compares.length, 0);
    assert.deepEqual(d1.sessions, []);
    assert.deepEqual(d1.prepared, []);
    assert.equal(d1.writeBatches, 0);
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
  });

  it("rejects a header that is not 43 base64url characters, without comparing", async () => {
    const { d1, env } = install();
    const secret = env.BOOTSTRAP_SECRET ?? "";
    const repeated = new Headers();
    repeated.append("Bootstrap-Secret", secret);
    repeated.append("Bootstrap-Secret", secret);
    const malformed: HeadersInit[] = [
      { "Bootstrap-Secret": secret.slice(0, 42) },
      { "Bootstrap-Secret": `${secret}A` },
      { "Bootstrap-Secret": `${secret.slice(0, 42)}+` },
      { "Bootstrap-Secret": `${secret.slice(0, 42)}/` },
      { "Bootstrap-Secret": `${secret.slice(0, 42)}=` },
      { "Bootstrap-Secret": `${secret.slice(0, 21)} ${secret.slice(22)}` },
      { "Bootstrap-Secret": `${secret.slice(0, 42)},` },
      { "Bootstrap-Secret": `${secret.slice(0, 20)},${secret.slice(0, 22)}` },
      repeated,
    ];
    for (const headers of malformed) {
      expectRejected(await send(env, { headers }), 401, "bootstrap_secret_required");
    }
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
    assert.equal(compares.length, 0);
    assert.deepEqual(d1.sessions, []);
  });

  it("ignores a secret anywhere but the Bootstrap-Secret header", async () => {
    const { d1, env } = install();
    const secret = env.BOOTSTRAP_SECRET ?? "";
    expectRejected(
      await send(env, {
        url: `${CLAIM_URL}?Bootstrap-Secret=${secret}&bootstrap_secret=${secret}`,
      }),
      401,
      "bootstrap_secret_required",
    );
    const elsewhere: HeadersInit[] = [
      { Authorization: `Bearer ${secret}` },
      { Authorization: secret },
      { Cookie: `Bootstrap-Secret=${secret}` },
      { "X-Bootstrap-Secret": secret },
    ];
    for (const headers of elsewhere) {
      expectRejected(await send(env, { headers }), 401, "bootstrap_secret_required");
    }
    const notFound = { status: 404, body: { ok: false, error: "not_found" } };
    assert.deepEqual(await send(env, { url: `${CLAIM_URL}/${secret}` }), notFound);
    // base64url characters form a valid method token.
    assert.deepEqual(await send(env, { method: secret }), notFound);
    assert.deepEqual(await send(env, { method: "GET", headers: withSecret(env) }), notFound);
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
    assert.equal(compares.length, 0);
    assert.deepEqual(d1.sessions, []);
  });

  it("rejects a non-empty body, including one that names an email", async () => {
    const { d1, env } = install();
    for (const body of ['{"owner_email":"mallory@example.com"}', "mallory@example.com", " "]) {
      expectRejected(
        await send(env, { headers: withSecret(env), body }),
        400,
        "claim_body_not_allowed",
      );
    }
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
    assert.equal(compares.length, 0);
    assert.deepEqual(d1.sessions, []);

    const empty = await send(env, { headers: withSecret(env), body: "" });
    assert.deepEqual(empty, { status: 201, body: { locked: true } });
  });

  it("reads no more of a body than its first byte", { timeout: 2000 }, async () => {
    const { d1, env } = install();
    // Each stream would hang if the Worker read past what it needs.
    let cancelled = false;
    const firstByte = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([123]));
      },
      pull: () => new Promise<void>(() => {}),
      cancel() {
        cancelled = true;
      },
    });
    expectRejected(
      await send(env, { headers: withSecret(env), body: firstByte }),
      400,
      "claim_body_not_allowed",
    );
    assert.equal(cancelled, true);

    const declared = new ReadableStream<Uint8Array>({ pull: () => new Promise<void>(() => {}) });
    expectRejected(
      await send(env, {
        headers: { ...withSecret(env), "Content-Length": "100" },
        body: declared,
      }),
      400,
      "claim_body_not_allowed",
    );

    const failing = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error(`stream failed ${env.OWNER_EMAIL}`));
      },
    });
    expectRejected(
      await send(env, { headers: withSecret(env), body: failing }),
      400,
      "claim_body_not_allowed",
    );
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
    assert.equal(compares.length, 0);

    const emptyChunks = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(0));
        controller.close();
      },
    });
    assert.deepEqual(await send(env, { headers: withSecret(env), body: emptyChunks }), {
      status: 201,
      body: { locked: true },
    });
  });

  it("requires a configured owner email and rejects the placeholder", async () => {
    for (const ownerEmail of [undefined, "", "   ", "<OWNER_EMAIL>", " <owner_email> "]) {
      for (const bootstrapSecret of [newSecret(), undefined]) {
        const { d1, env } = install({ OWNER_EMAIL: ownerEmail, BOOTSTRAP_SECRET: bootstrapSecret });
        expectRejected(
          await send(env, { headers: { "Bootstrap-Secret": bootstrapSecret ?? newSecret() } }),
          422,
          "owner_not_configured",
        );
        assert.deepEqual(rows(d1), NOTHING_WRITTEN);
        assert.deepEqual(d1.sessions, []);
      }
    }
    assert.equal(compares.length, 0);
  });

  it("fails closed when the bootstrap secret is not configured", async () => {
    const valid = newSecret();
    for (const bootstrapSecret of [
      undefined,
      "",
      valid.slice(0, 42),
      `${valid}=`,
      `${valid.slice(0, 42)}+`,
      `${valid.slice(0, 21)} ${valid.slice(22)}`,
      `${valid} `,
      ` ${valid}`,
      `${valid}\n`,
      `\t${valid}`,
    ]) {
      const { d1, env } = install({ BOOTSTRAP_SECRET: bootstrapSecret });
      expectRejected(
        await send(env, { headers: { "Bootstrap-Secret": valid } }),
        422,
        "bootstrap_not_configured",
      );
      assert.deepEqual(rows(d1), NOTHING_WRITTEN);
      assert.deepEqual(d1.sessions, []);
    }
    assert.equal(compares.length, 0);
  });

  it("rejects a wrong secret after a SHA-256 constant-time compare", async () => {
    const { d1, env } = install();
    const wrong = newSecret();
    expectRejected(
      await send(env, { headers: { "Bootstrap-Secret": wrong } }),
      401,
      "bootstrap_rejected",
    );
    assert.deepEqual(compares, [[sha256(wrong), sha256(env.BOOTSTRAP_SECRET ?? "")]]);
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
    assert.deepEqual(d1.sessions, []);
  });

  it("locks the owner email as entered and spends the secret", async () => {
    const { d1, env } = install();
    const secret = env.BOOTSTRAP_SECRET ?? "";
    assert.deepEqual(await send(env, { headers: withSecret(env) }), {
      status: 201,
      body: { locked: true },
    });
    assert.deepEqual(compares, [[sha256(secret), sha256(secret)]]);

    const { owner, spend } = rows(d1);
    assert.equal(owner.length, 1);
    const row = owner[0] as Record<string, unknown>;
    assert.equal(row.id, 1);
    assert.equal(row.owner_email, OWNER);
    assert.equal(row.claim_source, "first-boot");
    assert.equal(typeof row.claimed_at, "string");
    assert.equal(new Date(row.claimed_at as string).toISOString(), row.claimed_at);
    assert.deepEqual(spend, [
      { secret_sha256: sha256(secret).toString("hex"), spent_at: row.claimed_at },
    ]);
    assert.ok(d1.sessions.length > 0);
    assert.ok(d1.sessions.every((constraint) => constraint === "first-primary"));
  });

  it("refuses Origin null even with Sec-Fetch-Site same-origin, unlike POST /authorize", async () => {
    const { d1, env } = install();
    const configured: BridgeEnv = { ...env, BRIDGE_ORIGIN: "https://bridge.invalid" };
    const secret = configured.BOOTSTRAP_SECRET ?? "";
    for (const site of ["same-origin", "same-site", "cross-site", "none", null]) {
      const headers: Record<string, string> = { "Bootstrap-Secret": secret, Origin: "null" };
      if (site !== null) headers["Sec-Fetch-Site"] = site;
      expectRejected(await send(configured, { headers }), 403, "cross_site");
    }
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
    assert.equal(compares.length, 0);
    assert.deepEqual(d1.sessions, []);

    assert.deepEqual(await send(configured, {
      headers: { "Bootstrap-Secret": secret, Origin: "https://bridge.invalid", "Sec-Fetch-Site": "same-origin" },
    }), { status: 201, body: { locked: true } });
  });

  it("returns bootstrap_spent for a spent secret and changes nothing", async () => {
    const { d1, env } = install();
    await send(env, { headers: withSecret(env) });
    const locked = rows(d1);

    expectRejected(await send(env, { headers: withSecret(env) }), 409, "bootstrap_spent");
    const changedEmail = { ...env, OWNER_EMAIL: "grace@example.com" };
    expectRejected(
      await send(changedEmail, { headers: withSecret(changedEmail) }),
      409,
      "bootstrap_spent",
    );
    assert.deepEqual(rows(d1), locked);
    assert.equal(d1.writeBatches, 1);
  });

  it("returns owner_mismatch for a different email and spends nothing", async () => {
    const { d1, env } = install();
    await send(env, { headers: withSecret(env) });
    const locked = rows(d1);

    const other = { ...env, OWNER_EMAIL: "grace@example.com", BOOTSTRAP_SECRET: newSecret() };
    expectRejected(await send(other, { headers: withSecret(other) }), 409, "owner_mismatch");
    assert.deepEqual(rows(d1), locked);
    assert.equal(d1.writeBatches, 1);
  });

  it("returns owner_locked for the same owner by trim and lowercase, and spends nothing", async () => {
    const { d1, env } = install();
    await send(env, { headers: withSecret(env) });
    const locked = rows(d1);

    for (const ownerEmail of [OWNER, "ada@example.com", "  ADA@EXAMPLE.COM"]) {
      const again = { ...env, OWNER_EMAIL: ownerEmail, BOOTSTRAP_SECRET: newSecret() };
      expectRejected(await send(again, { headers: withSecret(again) }), 409, "owner_locked");
    }
    assert.deepEqual(rows(d1), locked);
    assert.equal(d1.writeBatches, 1);
  });

  it("checks the secret before any 409", async () => {
    const { d1, env } = install();
    await send(env, { headers: withSecret(env) });
    const locked = rows(d1);

    expectRejected(
      await send(env, { headers: { "Bootstrap-Secret": newSecret() } }),
      401,
      "bootstrap_rejected",
    );
    const other = { ...env, OWNER_EMAIL: "grace@example.com" };
    expectRejected(
      await send(other, { headers: { "Bootstrap-Secret": newSecret() } }),
      401,
      "bootstrap_rejected",
    );
    assert.deepEqual(rows(d1), locked);
  });

  it("lets one of two overlapping claims with the same secret win", { timeout: 5000 }, async () => {
    const { d1, env } = install();
    const sent = await race(d1, env, { ...env });
    assert.deepEqual(sent, [
      { status: 201, body: { locked: true } },
      { status: 409, body: { error: "bootstrap_spent" } },
    ]);
    assert.equal(d1.writeBatches, 2);
    const { owner, spend } = rows(d1);
    assert.equal(owner.length, 1);
    assert.equal(spend.length, 1);
  });

  it("maps a lost race with another secret to the owner rules", { timeout: 5000 }, async () => {
    for (const [loserEmail, error] of [
      ["ada@example.com", "owner_locked"],
      ["grace@example.com", "owner_mismatch"],
    ]) {
      const { d1, env } = install();
      // Two Worker versions in flight, each with its own secret.
      const loser = { ...env, OWNER_EMAIL: loserEmail, BOOTSTRAP_SECRET: newSecret() };
      const sent = await race(d1, env, loser);
      assert.equal(sent[0]?.status, 201);
      assert.deepEqual(sent[1], { status: 409, body: { error } });
      const { owner, spend } = rows(d1);
      assert.equal(owner.length, 1);
      assert.equal(spend.length, 1);
    }
  });

  it("fails closed without a second insert when the write fails", async () => {
    const { d1, env } = install();
    d1.failNextWrite(
      new Error(`D1_ERROR: ${env.OWNER_EMAIL} ${env.BOOTSTRAP_SECRET} SQLITE_ERROR`),
    );
    expectRejected(await send(env, { headers: withSecret(env) }), 500, "internal_error");
    assert.equal(d1.writeBatches, 1);
    assert.deepEqual(rows(d1), NOTHING_WRITTEN);
    assert.equal(
      logLines.some((line) => line.includes("SQLITE_ERROR")),
      false,
      "error text is not logged",
    );
  });

  it("fails closed without error text when a read fails", async () => {
    const before = install();
    before.d1.failRead(
      new Error(`D1_ERROR: ${before.env.OWNER_EMAIL} ${before.env.BOOTSTRAP_SECRET} SQLITE_BUSY`),
    );
    expectRejected(
      await send(before.env, { headers: withSecret(before.env) }),
      500,
      "internal_error",
    );
    assert.equal(before.d1.writeBatches, 0);
    assert.deepEqual(rows(before.d1), NOTHING_WRITTEN);

    // The write fails, then the re-read of the primary fails too.
    const reread = install();
    reread.d1.failNextWrite(new Error("D1_ERROR: SQLITE_CONSTRAINT"));
    reread.d1.failRead(
      new Error(`D1_ERROR: ${reread.env.OWNER_EMAIL} ${reread.env.BOOTSTRAP_SECRET} SQLITE_BUSY`),
      1,
    );
    expectRejected(
      await send(reread.env, { headers: withSecret(reread.env) }),
      500,
      "internal_error",
    );
    assert.equal(reread.d1.writeBatches, 1);
    assert.deepEqual(rows(reread.d1), NOTHING_WRITTEN);
    assert.equal(
      logLines.some((line) => line.includes("SQLITE_")),
      false,
      "error text is not logged",
    );
  });

  it("enforces the design's constraints in the migration", () => {
    const { d1 } = install();
    const hash = createHash("sha256").update("constraint").digest("hex");
    d1.sqlite.exec(
      `INSERT INTO owner_lock VALUES (1, 'a@example.com', 't', 'first-boot');
       INSERT INTO bootstrap_secret_spend VALUES ('${hash}', 't');`,
    );
    for (const sql of [
      "INSERT INTO owner_lock VALUES (1, 'b@example.com', 't', 'first-boot')",
      "INSERT INTO owner_lock VALUES (2, 'b@example.com', 't', 'first-boot')",
      `INSERT INTO bootstrap_secret_spend VALUES ('${hash}', 't')`,
      "INSERT INTO bootstrap_secret_spend VALUES (NULL, 't')",
      "INSERT INTO bootstrap_secret_spend VALUES ('', 't')",
    ]) {
      assert.throws(() => d1.sqlite.exec(sql), /constraint failed/i, sql);
    }
    d1.sqlite.exec("DELETE FROM owner_lock");
    for (const sql of [
      "INSERT INTO owner_lock VALUES (1, '   ', 't', 'first-boot')",
      "INSERT INTO owner_lock VALUES (1, NULL, 't', 'first-boot')",
      "INSERT INTO owner_lock VALUES (1, 'a@example.com', 't', 'other')",
    ]) {
      assert.throws(() => d1.sqlite.exec(sql), /constraint failed/i, sql);
    }
  });

  it("keeps spend rows after the operator deletes the owner row", async () => {
    const { d1, env } = install();
    await send(env, { headers: withSecret(env) });
    d1.sqlite.exec("DELETE FROM owner_lock WHERE id = 1;");

    expectRejected(await send(env, { headers: withSecret(env) }), 409, "bootstrap_spent");
    assert.equal(rows(d1).owner.length, 0);
    assert.equal(d1.writeBatches, 1);

    const fresh = { ...env, BOOTSTRAP_SECRET: newSecret() };
    assert.deepEqual(await send(fresh, { headers: withSecret(fresh) }), {
      status: 201,
      body: { locked: true },
    });
    assert.equal(rows(d1).spend.length, 2);
  });

  // Runs every claim outcome itself, then checks the statements that this and
  // every earlier test prepared.
  it("issues only owner-lock reads and the design's two INSERT statements", { timeout: 5000 }, async () => {
    const { d1, env } = install();
    await send(env, { headers: withSecret(env) });
    await send(env, { headers: withSecret(env) });
    const again = { ...env, BOOTSTRAP_SECRET: newSecret() };
    await send(again, { headers: withSecret(again) });
    const raced = install();
    await race(raced.d1, raced.env, { ...raced.env, BOOTSTRAP_SECRET: newSecret() });
    const failing = install();
    failing.d1.failNextWrite(new Error("D1_ERROR"));
    await send(failing.env, { headers: withSecret(failing.env) });
    assert.equal(rows(d1).owner.length, 1);

    const normalize = (sql: string) => sql.replace(/\s+/g, " ").trim().replace(/;$/, "");
    const design = readFileSync(
      resolve(dirname(fileURLToPath(import.meta.url)), "../docs/design/owner-lock.md"),
      "utf8",
    );
    const insertBlock = [...design.matchAll(/```sql\n([\s\S]*?)```/g)]
      .map((match) => match[1] ?? "")
      .find((block) => block.includes("INSERT INTO owner_lock"));
    assert.notEqual(insertBlock, undefined);
    const designInserts = (insertBlock ?? "")
      .split(";")
      .map(normalize)
      .filter((sql) => sql !== "");
    assert.equal(designInserts.length, 2);

    const issued = new Set(doubles.flatMap((double) => double.prepared.map(normalize)));
    for (const insert of designInserts) {
      assert.ok(issued.has(insert), insert);
    }
    for (const sql of issued) {
      if (designInserts.includes(sql)) {
        continue;
      }
      assert.match(sql, /^SELECT /, sql);
      assert.doesNotMatch(
        sql,
        /\b(INSERT|UPDATE|DELETE|REPLACE|UPSERT|DROP|ALTER|CREATE|PRAGMA|ATTACH|VACUUM)\b/i,
        sql,
      );
      const tables = [...sql.matchAll(/\b(?:FROM|JOIN)\s+(\w+)/gi)].map((match) => match[1]);
      assert.ok(tables.length > 0, sql);
      for (const table of tables) {
        assert.ok(table === "owner_lock" || table === "bootstrap_secret_spend", sql);
      }
    }
    const constraints = doubles.flatMap((double) => double.sessions);
    assert.ok(constraints.every((constraint) => constraint === "first-primary"));
  });
});
