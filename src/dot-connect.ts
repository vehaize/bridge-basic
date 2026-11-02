/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { CONNECT_RESULT_TTL_SECONDS } from "./consent-idempotency.ts";

import { oauthClient, type OAuthParticipant } from "./participants.ts";
const CODE = /^[A-Za-z0-9_-]{43}$/;
const FIELDS = new Set(["connect_code", "client_id", "redirect_uri", "response_type", "code_challenge",
  "code_challenge_method", "resource", "scope", "state"]);
const LIMIT = 16 * 1024;
const ELIGIBLE = `SELECT c.owner_claimed_at FROM connect_code AS c
  JOIN owner_lock AS o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  WHERE c.code_sha256 = ?1 AND c.participant = ?3 AND c.used_at IS NULL
    AND c.expires_at > ?2 AND c.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`;
const GUARD = `EXISTS (SELECT 1 FROM connect_code AS c
  JOIN owner_lock AS o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  WHERE c.code_sha256 = ?1 AND c.participant = ?5 AND c.used_at IS NULL
    AND c.owner_claimed_at = ?2 AND c.expires_at > ?3
    AND c.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`;
const CODE_STATE = `SELECT c.owner_claimed_at AS owner, c.used_at AS used_at, p.id AS credential_id
  FROM connect_code AS c
  JOIN owner_lock AS o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  LEFT JOIN participant_credential AS p
    ON p.connect_code_sha256 = c.code_sha256 AND p.participant = ?3 AND p.revoked_at IS NULL
  WHERE c.code_sha256 = ?1 AND c.participant = ?3
    AND c.expires_at > ?2 AND c.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`;
const BOUND = `SELECT c.used_at AS used_at FROM participant_credential AS p
  JOIN connect_code AS c ON c.code_sha256 = p.connect_code_sha256
  WHERE p.id = ?1 AND p.connect_code_sha256 = ?2 AND p.participant = ?3
    AND c.participant = ?3 AND p.revoked_at IS NULL`;
/** Same guard, but the spend timestamp is ?4 so ?3 can be the spent record. */
const SPEND_GUARD = GUARD.replace("expires_at > ?3", "expires_at > ?4");
/** Spent-row replay. Expiry stays out of this read: the 120s window is the spend time. */
const REPLAY = `SELECT c.used_at AS used_at, p.id AS credential_id
  FROM connect_code AS c
  JOIN owner_lock AS o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  LEFT JOIN participant_credential AS p
    ON p.connect_code_sha256 = c.code_sha256 AND p.participant = ?2 AND p.revoked_at IS NULL
  WHERE c.code_sha256 = ?1 AND c.participant = ?2`;

/** How long a disconnected submit may hold the code before another submit replaces it. */
export const CLAIM_LEASE_MS = 10_000;
const CLAIM_POLL_MIN_MS = 25;
const CLAIM_POLL_MAX_MS = 500;
const PENDING_CREDENTIAL = /^credential_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * `used_at` is null while the code is open, the canonical pending JSON while
 * a claim is held, or the canonical spent JSON once D1 has spent the code.
 * A spent record is JSON, so it enters the CASE. It does not match: equality
 * with json_object rebuilds only the pending keys, and a spent record carries
 * the spend time, credential id, challenge, and redirect instead. Non-JSON
 * text, including an older ISO-8601 spend timestamp, takes ELSE and skips
 * json_*. D1 rejects a LIKE or GLOB pattern longer than 50 bytes. The
 * credential id is checked with length and substr; the only pattern is a
 * 12-byte class.
 */
export const PENDING_CLAIM_SQL = [
  "CASE WHEN json_valid(used_at) THEN",
  "  used_at = json_object(",
  "    'v', json_extract(used_at, '$.v'),",
  "    'kind', json_extract(used_at, '$.kind'),",
  "    'credential_id', json_extract(used_at, '$.credential_id'),",
  "    'until', json_extract(used_at, '$.until')",
  "  )",
  "  AND json_type(used_at, '$.v') = 'integer'",
  "  AND json_extract(used_at, '$.v') = 1",
  "  AND json_type(used_at, '$.kind') = 'text'",
  "  AND json_extract(used_at, '$.kind') = 'pending'",
  "  AND json_type(used_at, '$.credential_id') = 'text'",
  "  AND length(json_extract(used_at, '$.credential_id')) = 47",
  "  AND substr(json_extract(used_at, '$.credential_id'), 1, 11) = 'credential_'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 12) NOT GLOB '*[^0-9a-f-]*'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 20, 1) = '-'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 25, 1) = '-'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 30, 1) = '-'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 35, 1) = '-'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 26, 1) = '4'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 31, 1) IN ('8', '9', 'a', 'b')",
  "  AND length(replace(substr(json_extract(used_at, '$.credential_id'), 12), '-', '')) = 32",
  "  AND json_type(used_at, '$.until') = 'integer'",
  "  ELSE 0 END",
].join("\n");
const RELEASABLE = `participant = ?4 AND code_sha256 = ?1 AND used_at = ?2 AND (${PENDING_CLAIM_SQL})
  AND expires_at > ?3 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`;

/** Delay before the next claim or replay read. Attempt 0 is 25ms, then doubles, capped at 500ms. */
export function claimPollDelay(attempt: number): number {
  const step = Number.isInteger(attempt) && attempt > 0 ? Math.min(attempt, 5) : 0;
  return Math.min(CLAIM_POLL_MIN_MS * 2 ** step, CLAIM_POLL_MAX_MS);
}

/** Structural contract of the pinned 1.2.3 split API; no provider dependency installed here. */
export interface DotAuthorizationRequest {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string[];
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  resource?: string;
  issuer?: string;
}
export interface DotConnectDependencies {
  db: D1Database;
  /** Canonical server configuration; never derive it from the incoming URL. */
  resource: string;
  /** Bind to OAuthAuthorizationServer.getOAuthApi(env), pinned to 1.2.3. */
  oauth: {
    parseAuthRequest: (request: Request) => Promise<DotAuthorizationRequest>;
    completeAuthorization: (options: {
      request: DotAuthorizationRequest; userId: string; metadata: Record<string, never>;
      scope: string[]; props: { credential_id: string }; revokeExistingGrants: false;
    }) => Promise<{ redirectTo: string }>;
  };
  now?: () => number;
}

type Phase =
  | { kind: "absent" }
  | { kind: "open"; owner: string }
  | { kind: "pending"; owner: string; token: string; until: number }
  | { kind: "spent"; credentialId: string | null };

type Acquisition =
  | { kind: "held"; owner: string; credentialId: string; token: string }
  | { kind: "busy" }
  | { kind: "ineligible" }
  | { kind: "spent"; credentialId: string | null };

interface PendingClaim {
  credentialId: string;
  until: number;
}

function failure(status = 400, error = "connection_failed"): Response {
  return Response.json({ error }, { status, headers: { "Cache-Control": "no-store" } });
}
function redirect(location: string): Response {
  return new Response(null, { status: 303, headers: { Location: location, "Cache-Control": "no-store" } });
}
function acceptedRedirect(location: string, state: string, origin: string, expectedRedirect: string): boolean {
  let url: URL;
  try { url = new URL(location); } catch { return false; }
  const query = url.searchParams;
  return `${url.origin}${url.pathname}` === expectedRedirect && !url.username && !url.password && !url.hash
    && Boolean(query.get("code")) && query.get("iss") === origin && (query.get("state") ?? "") === state
    && [...query.keys()].every((key) => ["code", "state", "iss"].includes(key) && query.getAll(key).length === 1);
}
function instant(now: () => number): string {
  return new Date(now()).toISOString();
}
function unreachable(value: never): never {
  void value;
  throw new Error("internal_error");
}
class InvalidForm extends Error {}
class Oversize extends Error {}
async function form(request: Request): Promise<URLSearchParams> {
  const bytes = new Uint8Array(LIMIT);
  const reader = request.body?.getReader();
  let size = 0;
  if (reader) {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value.byteLength > LIMIT - size) {
          void reader.cancel().catch(() => {});
          throw new Oversize();
        }
        bytes.set(value, size); size += value.byteLength;
      }
    } finally { reader.releaseLock(); }
  }
  const params = new URLSearchParams(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, size)));
  for (const key of params.keys()) {
    if (!FIELDS.has(key) || params.getAll(key).length !== 1) throw new InvalidForm();
  }
  return params;
}
function oneResult(result: D1Result | undefined): D1Result {
  if (!result?.success || !Array.isArray(result.results)) throw new Error("internal_error");
  return result;
}
function changedRows(result: D1Result | undefined): number {
  const row = oneResult(result).results[0] as { changed?: unknown } | undefined;
  if (typeof row?.changed !== "number") throw new Error("internal_error");
  return row.changed;
}
function claimToken(credentialId: string, until: number): string {
  return JSON.stringify({ v: 1, kind: "pending", credential_id: credentialId, until });
}
interface SpentRecord {
  credentialId: string;
  challenge: string;
  location: string;
  at: string;
}
function spentToken(record: SpentRecord): string {
  return JSON.stringify({
    v: 1,
    kind: "spent",
    at: record.at,
    credential_id: record.credentialId,
    challenge: record.challenge,
    location: record.location,
  });
}
/** Same record without the redirect. The row stays a spend marker. */
function spentMarker(record: SpentRecord): string {
  return JSON.stringify({
    v: 1,
    kind: "spent",
    at: record.at,
    credential_id: record.credentialId,
    challenge: record.challenge,
  });
}
function canonicalInstant(value: string): boolean {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}
function spentReplay(usedAt: string): SpentRecord | null {
  let parsed: unknown;
  try { parsed = JSON.parse(usedAt); } catch { return null; }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const row = parsed as { v?: unknown; kind?: unknown; at?: unknown; credential_id?: unknown; challenge?: unknown; location?: unknown };
  if (row.v !== 1 || row.kind !== "spent") return null;
  if (typeof row.at !== "string" || !canonicalInstant(row.at)) return null;
  if (typeof row.credential_id !== "string" || !PENDING_CREDENTIAL.test(row.credential_id)) return null;
  if (typeof row.challenge !== "string" || !CODE.test(row.challenge)) return null;
  if (typeof row.location !== "string" || row.location.length === 0) return null;
  const record = { credentialId: row.credential_id, challenge: row.challenge, location: row.location, at: row.at };
  if (usedAt !== spentToken(record)) return null;
  return record;
}
function pendingClaim(usedAt: string): PendingClaim | null {
  let parsed: unknown;
  try { parsed = JSON.parse(usedAt); } catch { return null; }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const row = parsed as { v?: unknown; kind?: unknown; credential_id?: unknown; until?: unknown };
  if (row.v !== 1 || row.kind !== "pending") return null;
  if (typeof row.credential_id !== "string" || !PENDING_CREDENTIAL.test(row.credential_id)) return null;
  if (typeof row.until !== "number" || !Number.isInteger(row.until)) return null;
  if (usedAt !== claimToken(row.credential_id, row.until)) return null;
  return { credentialId: row.credential_id, until: row.until };
}
async function readPhase(session: D1DatabaseSession, hash: string, at: string, participant: OAuthParticipant): Promise<Phase> {
  const [result] = await session.batch([session.prepare(CODE_STATE).bind(hash, at, participant)]);
  const rows = oneResult(result).results;
  if (rows.length > 1) throw new Error("internal_error");
  const row = rows[0] as { owner?: unknown; used_at?: unknown; credential_id?: unknown } | undefined;
  if (!row) return { kind: "absent" };
  if (typeof row.owner !== "string") throw new Error("internal_error");
  if (row.used_at === null) {
    if (row.credential_id !== null) throw new Error("internal_error");
    return { kind: "open", owner: row.owner };
  }
  if (typeof row.used_at !== "string") throw new Error("internal_error");
  const pending = pendingClaim(row.used_at);
  if (pending) {
    if (row.credential_id !== null) throw new Error("internal_error");
    return { kind: "pending", owner: row.owner, token: row.used_at, until: pending.until };
  }
  if (row.credential_id !== null && typeof row.credential_id !== "string") throw new Error("internal_error");
  return { kind: "spent", credentialId: typeof row.credential_id === "string" ? row.credential_id : null };
}
/**
 * Clear the redirect after the replay window. Matching the stored text makes
 * a repeat a no-op and loses to any concurrent change of this row.
 */
async function clearSpentRedirect(
  session: D1DatabaseSession,
  hash: string,
  usedAt: string,
  marker: string,
  participant: OAuthParticipant,
): Promise<void> {
  await session.batch([
    session.prepare(`UPDATE connect_code SET used_at = ?2
      WHERE code_sha256 = ?1 AND participant = ?4 AND used_at = ?3`).bind(hash, marker, usedAt, participant),
  ]);
}
async function releaseToken(session: D1DatabaseSession, hash: string, token: string, at: string, participant: OAuthParticipant): Promise<boolean> {
  const [, changed] = await session.batch([
    session.prepare(`UPDATE connect_code SET used_at = NULL WHERE ${RELEASABLE}`).bind(hash, token, at, participant),
    session.prepare("SELECT changes() AS changed"),
  ]);
  return changedRows(changed) === 1;
}
async function stillOpen(session: D1DatabaseSession, hash: string, at: string, participant: OAuthParticipant): Promise<boolean> {
  const [result] = await session.batch([session.prepare(ELIGIBLE).bind(hash, at, participant)]);
  const rows = oneResult(result).results;
  if (rows.length > 1) throw new Error("internal_error");
  return rows.length === 1;
}
async function boundSpend(session: D1DatabaseSession, credentialId: string, hash: string, participant: OAuthParticipant): Promise<boolean> {
  const [result] = await session.batch([session.prepare(BOUND).bind(credentialId, hash, participant)]);
  const rows = oneResult(result).results;
  if (rows.length > 1) throw new Error("internal_error");
  if (rows.length === 0) return false;
  const used = (rows[0] as { used_at?: unknown }).used_at;
  if (typeof used !== "string") throw new Error("internal_error");
  return pendingClaim(used) === null;
}

/**
 * Unmounted POST completion only: no consent page, code provisioning, token
 * endpoint, router import, logging or network implementation. Requires the
 * canonical connect_code table from migrations/0004_connect_code.sql.
 * The code authorizes one connection; request fields never select its owner.
 */
export async function completeParticipantConnection(request: Request, deps: DotConnectDependencies, expectedParticipant?: OAuthParticipant): Promise<Response> {
  if (request.method !== "POST") return failure(405, "method_not_allowed");
  if (request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase() !== "application/x-www-form-urlencoded") {
    return failure(415, "unsupported_media_type");
  }
  let params: URLSearchParams;
  try { params = await form(request); }
  catch (error) { return error instanceof Oversize ? failure(413, "body_too_large") : failure(); }

  try {
    const resource = new URL(deps.resource);
    if (resource.protocol !== "https:" || deps.resource !== `${resource.origin}/mcp`) throw new Error("internal_error");
    const client = oauthClient(params.get("client_id"));
    if (!client || (expectedParticipant !== undefined && client.participant !== expectedParticipant)) return failure();
    const participant = client.participant;
    // Keep the connect code exclusively in the POST body, including on rejects.
    if (request.url !== `${resource.origin}/authorize`
      || params.get("client_id") !== client.clientId || params.get("redirect_uri") !== client.redirectUri
      || params.get("response_type") !== "code" || params.get("resource") !== deps.resource
      || params.get("code_challenge_method") !== "S256" || !CODE.test(params.get("code_challenge") ?? "")
      || !CODE.test(params.get("connect_code") ?? "")) return failure();
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(params.get("connect_code")!));
    const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const challenge = params.get("code_challenge") ?? "";
    const state = params.get("state") ?? "";
    const clock = deps.now ?? Date.now;
    const session = deps.db.withSession("first-primary");
    const at = () => instant(clock);

    const readReplay = async (): Promise<string | null> => {
      const [result] = await session.batch([session.prepare(REPLAY).bind(hash, participant)]);
      const rows = oneResult(result).results;
      if (rows.length > 1) throw new Error("internal_error");
      const row = rows[0] as { used_at?: unknown; credential_id?: unknown } | undefined;
      if (!row) return null;
      if (row.used_at === null) return null;
      if (typeof row.used_at !== "string") throw new Error("internal_error");
      if (row.credential_id !== null && typeof row.credential_id !== "string") throw new Error("internal_error");
      const replay = spentReplay(row.used_at);
      if (!replay) return null;
      if (clock() - Date.parse(replay.at) > CONNECT_RESULT_TTL_SECONDS * 1000) {
        await clearSpentRedirect(session, hash, row.used_at, spentMarker(replay), participant);
        return null;
      }
      if (typeof row.credential_id !== "string" || replay.credentialId !== row.credential_id) return null;
      if (replay.challenge !== challenge) return null;
      if (!acceptedRedirect(replay.location, state, resource.origin, client.redirectUri)) return null;
      return replay.location;
    };
    const tryClaim = async (owner: string): Promise<Acquisition | null> => {
      const credentialId = `credential_${crypto.randomUUID()}`;
      const token = claimToken(credentialId, clock() + CLAIM_LEASE_MS);
      const [, changed] = await session.batch([
        session.prepare(`UPDATE connect_code SET used_at = ?4 WHERE code_sha256 = ?1 AND used_at IS NULL AND ${GUARD}`)
          .bind(hash, owner, at(), token, participant),
        session.prepare("SELECT changes() AS changed"),
      ]);
      return changedRows(changed) === 1 ? { kind: "held", owner, credentialId, token } : null;
    };
    const acquire = async (): Promise<Acquisition> => {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const phase = await readPhase(session, hash, at(), participant);
        switch (phase.kind) {
          case "absent":
            return { kind: "ineligible" };
          case "spent":
            return { kind: "spent", credentialId: phase.credentialId };
          case "pending":
            if (phase.until > clock()) return { kind: "busy" };
            if (!await releaseToken(session, hash, phase.token, at(), participant)) continue;
            break;
          case "open":
            break;
          default:
            unreachable(phase);
        }
        const held = await tryClaim(phase.owner);
        if (held) return held;
      }
      return { kind: "busy" };
    };
    const pause = async (attempt: number): Promise<number> => {
      await new Promise((resolve) => setTimeout(resolve, claimPollDelay(attempt)));
      return attempt + 1;
    };
    const waitForResolution = async (): Promise<{ kind: "redirect"; location: string } | { kind: "acquire" } | { kind: "stop" }> => {
      const started = Date.now();
      let attempt = 0;
      for (;;) {
        const location = await readReplay();
        if (location) return { kind: "redirect", location };
        const phase = await readPhase(session, hash, at(), participant);
        switch (phase.kind) {
          case "open":
            return { kind: "acquire" };
          case "pending":
            if (phase.until <= clock()) return { kind: "acquire" };
            if (Date.now() - started >= CLAIM_LEASE_MS) return { kind: "stop" };
            attempt = await pause(attempt);
            break;
          case "absent":
            return { kind: "stop" };
          case "spent": {
            const replay = await readReplay();
            return replay ? { kind: "redirect", location: replay } : { kind: "stop" };
          }
          default:
            unreachable(phase);
        }
      }
    };
    const runHeld = async (held: Extract<Acquisition, { kind: "held" }>): Promise<Response> => {
      const release = () => releaseToken(session, hash, held.token, at(), participant);
      const onAbort = () => { void release().catch(() => {}); };
      request.signal.addEventListener("abort", onAbort, { once: true });
      try {
        if (request.signal.aborted) {
          await release();
          return failure(500, "internal_error");
        }
        params.delete("connect_code");
        const parsed = await deps.oauth.parseAuthRequest(new Request(`${resource.origin}/authorize?${params}`));
        if (parsed.clientId !== client.clientId || parsed.redirectUri !== client.redirectUri || parsed.responseType !== "code"
          || parsed.resource !== deps.resource || parsed.issuer !== resource.origin
          || parsed.codeChallenge !== params.get("code_challenge") || parsed.codeChallengeMethod !== "S256") {
          throw new Error("internal_error");
        }
        const completed = await deps.oauth.completeAuthorization({
          request: parsed, userId: participant, metadata: {}, scope: parsed.scope,
          props: { credential_id: held.credentialId }, revokeExistingGrants: false,
        });
        if (!acceptedRedirect(completed.redirectTo, parsed.state, resource.origin, client.redirectUri)) throw new Error("internal_error");
        if (request.signal.aborted) {
          await release();
          return failure(500, "internal_error");
        }
        const owned = await readPhase(session, hash, at(), participant);
        if (owned.kind !== "pending" || owned.token !== held.token) {
          const replay = await readReplay();
          if (replay) return redirect(replay);
          await release();
          return await stillOpen(session, hash, at(), participant) ? failure(500, "internal_error") : failure();
        }
        const location = completed.redirectTo;
        const stamp = at();
        const spent = spentToken({ credentialId: held.credentialId, challenge, location, at: stamp });
        let results: D1Result[];
        try {
          results = await session.batch([
            session.prepare(`UPDATE connect_code SET used_at = NULL WHERE ${RELEASABLE}`)
              .bind(hash, held.token, stamp, participant),
            session.prepare(`UPDATE participant_credential SET revoked_at = ?3
              WHERE participant = ?5 AND revoked_at IS NULL AND ${GUARD}`).bind(hash, held.owner, stamp, null, participant),
            session.prepare(`INSERT INTO participant_credential
              (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at)
              SELECT ?4, ?5, 'oauth_grant', ?1, ?2, ?3 WHERE ${GUARD}`).bind(hash, held.owner, stamp, held.credentialId, participant),
            session.prepare("SELECT changes() AS changed"),
            session.prepare(`UPDATE connect_code SET used_at = ?3 WHERE code_sha256 = ?1 AND ${SPEND_GUARD}`)
              .bind(hash, held.owner, spent, stamp, participant),
            // Assert completion INSIDE the transaction. SQLite's clock can advance
            // between statements: an expiry after revocation/insertion must roll
            // everything back. The existing NOT NULL constraint supplies ABORT;
            // successful batches insert no assertion row and need no new schema.
            session.prepare(`INSERT INTO participant_credential
              (id, participant, kind, connect_code_sha256, owner_claimed_at, created_at)
              SELECT NULL, ?6, 'oauth_grant', ?1, ?2, ?5 WHERE NOT EXISTS (
                SELECT 1 FROM participant_credential AS p JOIN connect_code AS c ON c.code_sha256 = p.connect_code_sha256
                WHERE p.id = ?4 AND p.participant = ?6 AND c.participant = ?6 AND p.owner_claimed_at = ?2 AND p.revoked_at IS NULL
                  AND c.code_sha256 = ?1 AND c.owner_claimed_at = ?2 AND c.used_at = ?3
              )`).bind(hash, held.owner, spent, held.credentialId, stamp, participant),
          ]);
        } catch {
          // No mutation retry, including an ambiguous response after commit.
          let stored = false;
          try {
            stored = await boundSpend(session, held.credentialId, hash, participant);
          } catch {
            throw new Error("internal_error");
          }
          if (stored) return failure(500, "internal_error");
          await release();
          return await stillOpen(session, hash, at(), participant) ? failure(500, "internal_error") : failure();
        }
        if (results.length !== 6 || results.some((result) => !result.success) || changedRows(results[3]) !== 1) {
          if (!await boundSpend(session, held.credentialId, hash, participant)) await release();
          throw new Error("internal_error");
        }
        return redirect(location);
      } catch (error) {
        try {
          if (!await boundSpend(session, held.credentialId, hash, participant)) await release();
        } catch { /* a read failure keeps the claim; the lease releases it */ }
        throw error;
      } finally {
        request.signal.removeEventListener("abort", onAbort);
      }
    };

    const first = await readReplay();
    if (first) return redirect(first);
    if (request.signal.aborted) return failure(500, "internal_error");
    const acquired = await acquire();
    switch (acquired.kind) {
      case "held":
        return await runHeld(acquired);
      case "ineligible":
        return failure();
      case "spent": {
        if (!acquired.credentialId) return failure();
        const location = await readReplay();
        return location ? redirect(location) : failure();
      }
      case "busy": {
        const waited = await waitForResolution();
        switch (waited.kind) {
          case "redirect":
            return redirect(waited.location);
          case "stop":
            return failure();
          case "acquire": {
            const retry = await acquire();
            if (retry.kind === "held") return await runHeld(retry);
            if (retry.kind === "spent" && retry.credentialId) {
              const location = await readReplay();
              if (location) return redirect(location);
            }
            return failure();
          }
          default:
            unreachable(waited);
        }
      }
      default:
        unreachable(acquired);
    }
  } catch {
    return failure(500, "internal_error");
  }
}

/** Legacy entry point; production uses the shared participant implementation. */
export async function completeDotConnection(request: Request, deps: DotConnectDependencies): Promise<Response> {
  return completeParticipantConnection(request, deps, "dot");
}
