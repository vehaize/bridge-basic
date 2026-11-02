/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { logError, logInfo } from "./log.ts";

// `wrangler types` reads only the Wrangler config. BOOTSTRAP_SECRET is a Worker
// secret that is absent outside a claim, so the claim types its inputs here.
export interface OwnerClaimEnv {
  DB: D1Database;
  OWNER_EMAIL?: string;
  BOOTSTRAP_SECRET?: string;
}

type ClaimError =
  | "bootstrap_secret_required"
  | "claim_body_not_allowed"
  | "owner_not_configured"
  | "bootstrap_not_configured"
  | "bootstrap_rejected"
  | "bootstrap_spent"
  | "owner_mismatch"
  | "owner_locked"
  | "internal_error";

interface Rejection {
  status: 400 | 401 | 409 | 422 | 500;
  error: ClaimError;
}

interface LockState {
  ownerEmail: string | null;
  spent: boolean;
}

// 32 random bytes as base64url without padding.
const SECRET_FORMAT = /^[A-Za-z0-9_-]{43}$/;

/** The candidate secret, once it has the required form. Comparison comes later. */
export function presentedBootstrapSecret(request: Request): string | null {
  const presented = request.headers.get("Bootstrap-Secret");
  if (presented === null || !SECRET_FORMAT.test(presented)) return null;
  return presented;
}

const PLACEHOLDER_KEY = emailKey("<OWNER_EMAIL>");

const READ_OWNER = "SELECT owner_email FROM owner_lock WHERE id = 1";
const READ_SPEND =
  "SELECT 1 AS spent FROM bootstrap_secret_spend WHERE secret_sha256 = ?1";
const INSERT_OWNER =
  "INSERT INTO owner_lock (id, owner_email, claimed_at, claim_source) VALUES (1, ?1, ?2, 'first-boot')";
const INSERT_SPEND =
  "INSERT INTO bootstrap_secret_spend (secret_sha256, spent_at) VALUES (?3, ?2)";

export async function claimOwner(
  request: Request,
  env: OwnerClaimEnv,
): Promise<Response> {
  let rejection: Rejection | null;
  try {
    rejection = await decideClaim(request, env);
  } catch {
    // Error text is not logged. It can carry request or binding data.
    rejection = { status: 500, error: "internal_error" };
  }

  if (rejection === null) {
    logInfo({ message: "owner claim", status: 201 });
    return Response.json({ locked: true }, { status: 201 });
  }

  const log = rejection.status === 500 ? logError : logInfo;
  log({ message: "owner claim", status: rejection.status, error: rejection.error });
  return Response.json({ error: rejection.error }, { status: rejection.status });
}

async function decideClaim(
  request: Request,
  env: OwnerClaimEnv,
): Promise<Rejection | null> {
  // Workers join repeated header fields with ", ", which fails the format.
  const presented = presentedBootstrapSecret(request);
  if (presented === null) {
    return { status: 401, error: "bootstrap_secret_required" };
  }

  if (await hasBody(request)) {
    return { status: 400, error: "claim_body_not_allowed" };
  }

  const ownerEmail = env.OWNER_EMAIL;
  if (typeof ownerEmail !== "string" || !isConfiguredEmail(ownerEmail)) {
    return { status: 422, error: "owner_not_configured" };
  }

  const configured = env.BOOTSTRAP_SECRET;
  if (typeof configured !== "string" || !SECRET_FORMAT.test(configured)) {
    return { status: 422, error: "bootstrap_not_configured" };
  }

  const [presentedDigest, configuredDigest] = await Promise.all([
    sha256(presented),
    sha256(configured),
  ]);
  if (!crypto.subtle.timingSafeEqual(presentedDigest, configuredDigest)) {
    return { status: 401, error: "bootstrap_rejected" };
  }

  const secretHash = toHex(configuredDigest);
  const session = env.DB.withSession("first-primary");
  const before = await readLock(session, secretHash);
  const conflict = lockConflict(before, ownerEmail);
  if (conflict !== null) {
    return conflict;
  }

  const claimedAt = new Date().toISOString();
  try {
    await session.batch([
      session.prepare(INSERT_OWNER).bind(ownerEmail, claimedAt),
      // ?1 is unused: the design numbers the batch's parameters across both statements.
      session.prepare(INSERT_SPEND).bind(null, claimedAt, secretHash),
    ]);
  } catch {
    // Another claim won the primary keys, or the write failed. Map what the
    // primary now holds and never insert again.
    const after = await readLock(env.DB.withSession("first-primary"), secretHash);
    return lockConflict(after, ownerEmail) ?? { status: 500, error: "internal_error" };
  }

  return null;
}

function lockConflict(state: LockState, ownerEmail: string): Rejection | null {
  if (state.spent) {
    return { status: 409, error: "bootstrap_spent" };
  }
  if (state.ownerEmail === null) {
    return null;
  }
  return emailKey(state.ownerEmail) === emailKey(ownerEmail)
    ? { status: 409, error: "owner_locked" }
    : { status: 409, error: "owner_mismatch" };
}

async function readLock(
  session: D1DatabaseSession,
  secretHash: string,
): Promise<LockState> {
  const [owner, spend] = await session.batch<Record<string, unknown>>([
    session.prepare(READ_OWNER),
    session.prepare(READ_SPEND).bind(secretHash),
  ]);
  const stored = owner.results[0]?.owner_email;
  return {
    ownerEmail: typeof stored === "string" ? stored : null,
    spent: spend.results.length > 0,
  };
}

// A declared length counts without a read. Otherwise this reads until the first
// byte or the end, so a large body is never buffered. A failed stream counts.
async function hasBody(request: Request): Promise<boolean> {
  if (Number(request.headers.get("Content-Length")) > 0) {
    return true;
  }
  if (request.body === null) {
    return false;
  }
  const reader = request.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        return false;
      }
      if (value.byteLength > 0) {
        await reader.cancel();
        return true;
      }
    }
  } catch {
    return true;
  }
}

function emailKey(email: string): string {
  return email.trim().toLowerCase();
}

function isConfiguredEmail(email: string): boolean {
  const key = emailKey(email);
  return key !== "" && key !== PLACEHOLDER_KEY;
}

function sha256(value: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
}

function toHex(digest: ArrayBuffer): string {
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
