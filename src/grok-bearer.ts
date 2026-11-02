/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { ParticipantDisabled } from "./participant-status.ts";

// Authentication scheme is case-insensitive; the token prefix and bytes are
// not. Comma-joined repeated headers, other schemes and non-Grok tokens fail
// before hashing or storage. Token material is accepted only from this header.
const BEARER = /^([A-Za-z]+) +(admrn_gb_[A-Za-z0-9_-]{43})$/;

const READ_PRINCIPAL = `SELECT p.id AS participant, p.enabled AS enabled
  FROM participant_credential AS c
  JOIN participant AS p ON p.id = c.participant
  JOIN owner_lock AS o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  WHERE c.token_sha256 = ?1 AND c.kind = 'bearer'
    AND c.participant = 'grok_bot'
    AND c.revoked_at IS NULL
  LIMIT 1`;

/**
 * Unmounted, read-only verifier. No issuance, rotation, grants, OAuth, session
 * cache, logging, or owner-table writes. The static Grok token has no TTL in
 * the canonical design. Every check reads the current owner/credential state.
 *
 * Production `/mcp` supplies this as the Grok half of getPrincipal.
 * Dot/OAuth credentials always fail here, regardless of their expiry.
 */
export async function verifyGrokBearer(request: Request, db: D1Database): Promise<"grok_bot" | null> {
  const match = BEARER.exec(request.headers.get("Authorization") ?? "");
  if (!match || match[1].toLowerCase() !== "bearer") return null;
  try {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(match[2]));
    const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    const session = db.withSession("first-primary");
    // One joined read in one primary batch observes the lock generation,
    // enabled participant and unrevoked credential together. No owner email,
    // raw token, token hash or credential metadata is returned to the caller.
    const [result] = await session.batch<{ participant: string; enabled: number }>([
      session.prepare(READ_PRINCIPAL).bind(hash),
    ]);
    if (!result?.success || !Array.isArray(result.results)) throw new Error("internal_error");
    if (result.results.length !== 1 || result.results[0].participant !== "grok_bot") return null;
    if (result.results[0].enabled === 0) throw new ParticipantDisabled();
    return result.results[0].enabled === 1 ? "grok_bot" : null;
  } catch (error) {
    if (error instanceof ParticipantDisabled) throw error;
    // The unmounted MCP adapter maps dependency exceptions to a fixed 500.
    // Never retain the original exception as a cause or echo/log its details.
    throw new Error("internal_error");
  }
}
