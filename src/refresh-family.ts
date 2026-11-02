/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { ParticipantDisabled } from "./participant-status.ts";

/** One recovery rotation after a lost response; never extended by recovery. */
export const REFRESH_PREVIOUS_GRACE_MS = 60_000;
/** Let a lock loser retry while the previous-token recovery window is open. */
export const REFRESH_BUSY_RETRY_AFTER_SECONDS = 1;
/**
 * Provider refresh-grant lifetime. It is fixed at code exchange: the provider has
 * no idle TTL configured, so a rotation never extends it.
 */
export const REFRESH_TOKEN_TTL_SECONDS = 2_592_000;
/**
 * Per-family refresh budget: the current token rotates at most once per interval.
 * The one-use previous-token grace retry is exempt, so a chain rotates at most
 * twice per interval. A deferred request returns 503 before any D1 or KV write.
 */
export const REFRESH_MIN_INTERVAL_MS = 15 * 60_000;
/**
 * Hard bound on recorded hashes per family. Within one fixed grant lifetime the
 * budget admits at most one budgeted rotation per interval (plus the first), each
 * with at most one grace retry, plus the enrolled token and a legacy successor.
 * History is never pruned while the family can still refresh: a forgotten
 * ancestor would become an unknown token whose reuse could not revoke the family.
 * A family at the bound fails closed like reuse instead of recording another row.
 */
export const REFRESH_HISTORY_MAX_ROWS = 2 * (Math.floor(REFRESH_TOKEN_TTL_SECONDS * 1000 / REFRESH_MIN_INTERVAL_MS) + 1) + 2;

export class RefreshFamilyRefused extends Error {
  constructor() { super("invalid_grant"); }
}
export class RefreshFamilyBusy extends Error {
  constructor() { super("unavailable"); }
}
/** The current token rotated within the budget interval. Nothing was written. */
export class RefreshFamilyDeferred extends Error {
  readonly retryAfterSeconds: number;
  constructor(retryAfterSeconds: number) {
    super("unavailable");
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
/**
 * The refresh could not be admitted. Nothing was written and the family was
 * not refused, so the same token can be presented again.
 */
export class RefreshFamilyUnavailable extends Error {
  readonly retryAfterSeconds = REFRESH_BUSY_RETRY_AFTER_SECONDS;
  constructor() {
    super("unavailable");
  }
}

interface FamilyRow {
  id: string;
  credential_id: string;
  participant: string;
  client_id: string;
  grant_id: string;
  current_sha256: string | null;
  previous_sha256: string | null;
  previous_until_ms: number | null;
  previous_used: number;
  position: number;
  pending_id: string | null;
  revoked_at: string | null;
  enabled: number;
}

const CREDENTIAL = `SELECT 1 FROM participant_credential c
  JOIN participant p ON p.id = c.participant
  JOIN owner_lock o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  WHERE c.id = oauth_refresh_family.credential_id AND c.kind = 'oauth_grant'
    AND c.participant = oauth_refresh_family.participant AND c.revoked_at IS NULL`;
// Admission checks the pause before the provider writes. A pause racing with
// an already admitted rotation must not revoke it or lose its response. Finish
// that rotation; the next request observes the pause. Owner/revoke checks remain.
const VALID_CREDENTIAL = `EXISTS (${CREDENTIAL})`;
const ACTIVE = `EXISTS (${CREDENTIAL} AND p.enabled = 1)`;
// Rows sit at positions 0..position, unique per family, so this position limit
// keeps one more insert within REFRESH_HISTORY_MAX_ROWS.
const ROOM = `position <= ${REFRESH_HISTORY_MAX_ROWS - 2}`;
// previous_until_ms is the last budgeted rotation plus the grace; a grace retry
// keeps it unchanged, so it also dates the last budgeted rotation.
const BUDGETED = `(previous_until_ms IS NULL OR previous_until_ms <= ?4 + ${REFRESH_PREVIOUS_GRACE_MS - REFRESH_MIN_INTERVAL_MS})`;
const GRACE = `(previous_sha256 = ?1 AND previous_used = 0 AND previous_until_ms >= ?4)`;
// Protocol revocation is never deferred or capped; only rotation is budgeted.
const ELIGIBLE = `(current_sha256 = ?1 OR ${GRACE})`;
const ROTATABLE = `(${ROOM} AND ((current_sha256 = ?1 AND ${BUDGETED}) OR ${GRACE}))`;
const READ_HASH = `SELECT f.*, p.enabled FROM oauth_refresh_token t
  JOIN oauth_refresh_family f ON f.id = t.family_id
  JOIN participant_credential c ON c.id = f.credential_id AND c.participant = f.participant
  JOIN participant p ON p.id = c.participant
  JOIN owner_lock o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  WHERE t.token_sha256 = ?1 AND f.client_id = ?2 AND c.revoked_at IS NULL`;

export interface FamilyIdentity {
  credentialId: string;
  participant: string;
  clientId: string;
  grantId: string;
}

/** Request-local state only. D1 is the lock and revocation authority. */
export class RefreshFamilyExchange {
  readonly db: D1Database;
  readonly nonce = crypto.randomUUID();
  readonly hash: string | null;
  readonly clientId: string | null;
  held: FamilyRow | null = null;
  reuse: FamilyRow | null = null;
  /** Eligible token left unclaimed because a KV pre-read said it could not rotate. */
  unclaimedEligible = false;

  readonly revocation: boolean;

  constructor(db: D1Database, hash: string | null, clientId: string | null, revocation = false) {
    this.db = db;
    this.hash = hash;
    this.clientId = clientId;
    this.revocation = revocation;
  }

  /**
   * Possession of a full previously recorded hash selects this family. One
   * conditional UPDATE claims it, before provider KV reads/writes, when
   * `claim` is true. A loser cannot wait on a stale provider snapshot and
   * become a grace success. `claim: false` still classifies deferral, pause,
   * busy, and reuse, but does not write: the caller already knows this
   * refresh cannot rotate, or it will claim later once client authentication
   * has succeeded. Unknown tokens gain no authority here; only a validated
   * callback can enroll.
   */
  async prepare(options?: { claim?: boolean }): Promise<void> {
    const claim = options?.claim !== false;
    if (this.hash === null || this.clientId === null) return;
    const nowMs = Date.now();
    const session = this.db.withSession("first-primary");
    const read = session.prepare(READ_HASH).bind(this.hash, this.clientId);
    const update = session.prepare(`UPDATE oauth_refresh_family SET pending_id = ?3
        WHERE client_id = ?2 AND pending_id IS NULL AND revoked_at IS NULL
          AND ${this.revocation ? ELIGIBLE : ROTATABLE} AND ${ACTIVE}
          AND EXISTS (SELECT 1 FROM oauth_refresh_token t WHERE t.family_id = oauth_refresh_family.id AND t.token_sha256 = ?1)`)
      .bind(this.hash, this.clientId, this.nonce, nowMs);
    const results = await session.batch<FamilyRow>(claim ? [update, read] : [read]);
    successful(results);
    const row = rows(results[claim ? 1 : 0])[0];
    if (!row) return;
    if (row.enabled === 0) throw new ParticipantDisabled();
    if (row.revoked_at !== null) throw new RefreshFamilyRefused();
    if (row.pending_id === this.nonce) {
      this.unclaimedEligible = false;
      this.held = row;
      return;
    }
    // Classify with the same clock and rules as the admission UPDATE above.
    const current = row.current_sha256 === this.hash;
    const grace = row.previous_sha256 === this.hash && row.previous_used === 0
      && row.previous_until_ms !== null && row.previous_until_ms >= nowMs;
    if (this.revocation) {
      if (row.pending_id !== null && (current || grace)) throw new RefreshFamilyBusy();
      this.unclaimedEligible = false;
      this.reuse = row;
      return;
    }
    // At the bound, even the current token fails closed like reuse.
    if (row.position > REFRESH_HISTORY_MAX_ROWS - 2) {
      this.unclaimedEligible = false;
      this.reuse = row;
      return;
    }
    const nextMs = row.previous_until_ms === null ? null
      : row.previous_until_ms - REFRESH_PREVIOUS_GRACE_MS + REFRESH_MIN_INTERVAL_MS;
    if (current && nextMs !== null && nextMs > nowMs) {
      throw new RefreshFamilyDeferred(Math.max(1, Math.ceil((nextMs - nowMs) / 1000)));
    }
    if (row.pending_id !== null && (current || grace)) throw new RefreshFamilyBusy();
    // A skipped claim for an eligible token is not reuse. A later provider
    // read that disagrees must retry, not refuse or revoke this family.
    const budgeted = nextMs === null || nextMs <= nowMs;
    if (!claim && row.pending_id === null && (grace || (current && budgeted))) {
      this.unclaimedEligible = true;
      return;
    }
    this.unclaimedEligible = false;
    this.reuse = row;
  }

  /** Called only after provider authentication, hash matching and decryption. */
  async validated(identity: FamilyIdentity): Promise<void> {
    // Reuse wins over an earlier eligible read. A late claim can find that the
    // token is now an ancestor; waiting for the next request would leave it
    // usable for one more try. A healthy retry has no reuse row.
    if (this.reuse) throw new RefreshFamilyRefused();
    // The provider accepted a token this request left unclaimed. Do not enroll
    // or refuse it from that stale pre-read; the caller retries with no write.
    if (this.unclaimedEligible && !this.held) throw new RefreshFamilyUnavailable();
    if (this.held) {
      const row = this.held;
      if (row.credential_id !== identity.credentialId || row.participant !== identity.participant
        || row.client_id !== identity.clientId || row.grant_id !== identity.grantId) throw new RefreshFamilyRefused();
      return;
    }
    // Initial code exchange, or first validated refresh of a pre-F4 grant.
    // No historical hashes can be reconstructed for a pre-enrollment grant.
    const id = `${identity.participant}:${identity.grantId}`;
    const session = this.db.withSession("first-primary");
    const result = await session.batch<FamilyRow>([
      session.prepare(`INSERT INTO oauth_refresh_family
        (id, credential_id, participant, client_id, grant_id, current_sha256, pending_id)
        SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 FROM participant_credential c
        JOIN participant p ON p.id = c.participant
        JOIN owner_lock o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
        WHERE c.id = ?2 AND c.participant = ?3 AND c.kind = 'oauth_grant' AND c.revoked_at IS NULL
        ON CONFLICT (id) DO NOTHING`)
        .bind(id, identity.credentialId, identity.participant, identity.clientId, identity.grantId, this.hash, this.nonce),
      session.prepare(`SELECT f.*, p.enabled FROM oauth_refresh_family f
        JOIN participant p ON p.id = f.participant WHERE f.id = ?1`).bind(id),
    ]);
    successful(result);
    const row = rows(result[1])[0];
    if (!row || row.revoked_at !== null) throw new RefreshFamilyRefused();
    if (row.pending_id !== this.nonce) {
      if (row.pending_id === null) throw new RefreshFamilyRefused();
      throw new RefreshFamilyBusy();
    }
    this.held = row;
    if (this.hash !== null) {
      successful(await session.batch([session.prepare(`INSERT INTO oauth_refresh_token (token_sha256, family_id, position)
        SELECT ?1, id, 0 FROM oauth_refresh_family WHERE id = ?2 AND pending_id = ?3 AND revoked_at IS NULL`)
        .bind(this.hash, id, this.nonce)]));
    }
  }

  /** The successor is recorded before the token response leaves this Worker. */
  async complete(token: string): Promise<void> {
    const row = this.held;
    if (!row || !token.startsWith(`${row.participant}:${row.grant_id}:`)) throw new RefreshFamilyRefused();
    const hash = await refreshTokenHash(token);
    const previous = this.hash;
    const grace = previous !== null && previous === row.previous_sha256;
    const until = grace ? row.previous_until_ms : previous === null ? null : Date.now() + REFRESH_PREVIOUS_GRACE_MS;
    const session = this.db.withSession("first-primary");
    const result = await session.batch<{ id: string }>([
      session.prepare(`INSERT INTO oauth_refresh_token (token_sha256, family_id, position)
        SELECT ?1, id, position + 1 FROM oauth_refresh_family
        WHERE id = ?2 AND pending_id = ?3 AND revoked_at IS NULL AND ${VALID_CREDENTIAL}`)
        .bind(hash, row.id, this.nonce),
      session.prepare(`UPDATE oauth_refresh_family SET current_sha256 = ?1, previous_sha256 = ?4,
        previous_until_ms = ?5, previous_used = ?6, position = position + 1, pending_id = NULL
        WHERE id = ?2 AND pending_id = ?3 AND revoked_at IS NULL AND ${VALID_CREDENTIAL}`)
        .bind(hash, row.id, this.nonce, previous, until, grace ? 1 : 0),
      session.prepare(`SELECT id FROM oauth_refresh_family WHERE id = ?1 AND current_sha256 = ?2
        AND pending_id IS NULL AND revoked_at IS NULL AND ${VALID_CREDENTIAL}`).bind(row.id, hash),
    ]);
    successful(result);
    if (rows(result[2]).length !== 1) throw new RefreshFamilyRefused();
    this.held = null;
  }

  /**
   * No provider write was attempted. Clear the claim without consuming a live
   * grace retry. A current-token refresh admission also starts the rotation
   * budget, so a repeated failure cannot write another claim until that
   * interval has passed. The budget and the grace share previous_until_ms.
   * Moving that timestamp must not reopen an already expired unused grace, so
   * an expired previous token is marked used. A window that is still open is
   * left unchanged. Revocation does not use that clock.
   */
  async release(): Promise<void> {
    if (!this.held) return;
    const row = this.held;
    const chargeBudget = !this.revocation && this.hash !== null && row.current_sha256 === this.hash;
    const nowMs = Date.now();
    const until = nowMs + REFRESH_PREVIOUS_GRACE_MS;
    const session = this.db.withSession("first-primary");
    // previous_until_ms is both the grace deadline and the budget clock. A
    // charge moves it forward only after an already expired unused grace is
    // marked used. A still-open window is not extended and is not consumed.
    const clearPending = chargeBudget
      ? `UPDATE oauth_refresh_family SET pending_id = NULL,
          previous_used = CASE
            WHEN previous_sha256 IS NOT NULL AND previous_used = 0
             AND (previous_until_ms IS NULL OR previous_until_ms < ?4)
            THEN 1 ELSE previous_used END,
          previous_until_ms = CASE
            WHEN previous_sha256 IS NOT NULL AND previous_used = 0
             AND previous_until_ms IS NOT NULL AND previous_until_ms >= ?4
            THEN previous_until_ms ELSE ?3 END
          WHERE id = ?1 AND pending_id = ?2`
      : `UPDATE oauth_refresh_family SET pending_id = NULL WHERE id = ?1 AND pending_id = ?2`;
    const clear = chargeBudget
      ? session.prepare(clearPending).bind(row.id, this.nonce, until, nowMs)
      : session.prepare(clearPending).bind(row.id, this.nonce);
    successful(await session.batch([
      session.prepare(`DELETE FROM oauth_refresh_family WHERE id = ?1 AND pending_id = ?2 AND current_sha256 IS NULL`)
        .bind(row.id, this.nonce),
      clear,
    ]));
    this.held = null;
  }

  /**
   * Whole-grant cleanup has no exchange callback for protocol revocation or a
   * used authorization code. Call only at the observed cleanup boundary, after
   * the provider matches the stored token/code hash and authenticated client.
   * A request's opaque grant reference alone is never revocation authority.
   */
  async revokeProviderGrant(participant: string, grantId: string): Promise<void> {
    if (this.clientId === null) throw new RefreshFamilyRefused();
    const session = this.db.withSession("first-primary");
    const results = await session.batch<FamilyRow>([
      session.prepare(`UPDATE oauth_refresh_family SET revoked_at = ?4
        WHERE participant = ?1 AND grant_id = ?2 AND client_id = ?3
          AND revoked_at IS NULL AND ${ACTIVE}`)
        .bind(participant, grantId, this.clientId, new Date().toISOString()),
      session.prepare(`SELECT f.*, p.enabled FROM oauth_refresh_family f
        JOIN participant_credential c ON c.id = f.credential_id AND c.participant = f.participant
        JOIN participant p ON p.id = c.participant
        JOIN owner_lock o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
        WHERE f.participant = ?1 AND f.grant_id = ?2 AND f.client_id = ?3`)
        .bind(participant, grantId, this.clientId),
      session.prepare("SELECT enabled FROM participant WHERE id = ?1").bind(participant),
    ]);
    successful(results);
    const row = rows(results[1])[0];
    // An unenrolled/stale-owner grant has no current D1 family authority to
    // infer. Preserve provider KV cleanup without guessing another credential.
    if (!row) {
      // The observed cleanup also authenticates the legacy grant's participant.
      // Reading its pause is safe without inferring a credential to revoke.
      if (rows(results[2])[0]?.enabled === 0) throw new ParticipantDisabled();
      return;
    }
    if (row.revoked_at === null) {
      if (row.enabled === 0) throw new ParticipantDisabled();
      throw new Error("internal_error");
    }
    if (this.held?.id === row.id) this.held = null;
    if (this.reuse?.id === row.id) this.reuse = null;
  }

  /** Hash-proven reuse, owner revoke, or uncertain provider mutation fails closed. */
  async revoke(): Promise<void> {
    const row = this.held ?? this.reuse;
    if (!row) return;
    const session = this.db.withSession("first-primary");
    successful(await session.batch([session.prepare(`UPDATE oauth_refresh_family SET revoked_at = ?2
      WHERE id = ?1 AND revoked_at IS NULL`).bind(row.id, new Date().toISOString())]));
    this.held = null;
    this.reuse = null;
  }
}

function rows<T>(result: D1Result<T> | undefined): T[] {
  if (!result?.success || !Array.isArray(result.results)) throw new Error("internal_error");
  return result.results;
}

function successful(results: readonly D1Result<unknown>[]): void {
  if (results.some(result => !result.success)) throw new Error("internal_error");
}

export async function refreshTokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}
