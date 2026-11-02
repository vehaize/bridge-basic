/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { oauthClient, oauthParticipant, type OAuthParticipant } from "./participants.ts";
import { ParticipantDisabled } from "./participant-status.ts";
// Matches the pinned provider's opaque bearer parsing, including its ':' token
// separators. No token bytes or unverified token fields determine the caller.
const BEARER = /^Bearer[\t ]+([^\s,]+)$/i;
// Revocation source of truth is D1 participant_credential.revoked_at, read on
// every /mcp call. The KV grant record is not revocation authority, and this
// check does not follow a KV delete or a stale KV grant.
const READ_PRINCIPAL = `SELECT p.id AS participant, p.enabled AS enabled
  FROM participant_credential AS c
  JOIN participant AS p ON p.id = c.participant
  JOIN owner_lock AS o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  WHERE c.id = ?1 AND c.kind = 'oauth_grant'
    AND c.participant = ?2
    AND c.revoked_at IS NULL
  LIMIT 1`;

export interface DotOAuthDependencies {
  db: D1Database;
  /** Canonical HTTPS /mcp identifier from server configuration, never the request. */
  resource: string;
  /**
   * Server-only binding to @cloudflare/workers-oauth-provider 1.2.3's
   * OAuthAuthorizationServer.validateToken(resource, token, env).
   * It must authenticate the token and return ValidatedAccessToken or null.
   * Never substitute unwrapToken, decoded client claims, or a test resolver.
   * Unknown here requires runtime checking of the library's returned context.
   */
  validateToken: (resource: string, token: string) => Promise<unknown>;
  /**
   * Scope stored for this Bridge-issued grant. Null means the grant is missing
   * or its stored scope is ambiguous. A thrown error is a lookup failure.
   */
  readGrantScope: (userId: string, grantId: string) => Promise<string[] | null>;
  /** Server clock in milliseconds; injection is for isolated deterministic tests. */
  now?: () => number;
}

/** KV or provider lookup failed. The adapter returns 503 and must not treat this as a principal. */
export class DotAuthUnavailable extends Error {
  constructor() {
    super("unavailable");
    this.name = "DotAuthUnavailable";
  }
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unexpired(expiresAt: number, now: () => number): boolean {
  const milliseconds = now();
  if (!Number.isFinite(milliseconds)) throw new Error("internal_error");
  return expiresAt > milliseconds / 1000;
}

/**
 * Opaque token grammar of @cloudflare/workers-oauth-provider 1.2.3:
 * `userId:grantId:secret`. The library splits on `:` into exactly three parts
 * and stores `grant:${userId}:${grantId}`, so a grant id contains no colon.
 */
function issuedGrant(token: string): { userId: string; grantId: string } | null {
  const parts = token.split(":");
  if (parts.length !== 3) return null;
  const [userId, grantId, secret] = parts;
  if (!oauthParticipant(userId) || !grantId || !/^[A-Za-z0-9_-]{1,128}$/.test(grantId) || !secret) return null;
  return { userId, grantId };
}

function stringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function sameScope(tokenScope: string[], grantScope: string[]): boolean {
  return tokenScope.length === grantScope.length && tokenScope.every((entry, index) => entry === grantScope[index]);
}

/** Stored grant scope that the presented token did not equal. Not a principal. */
export interface InsufficientDotScope {
  readonly decision: "insufficient_scope";
  readonly scope: readonly string[];
}

/**
 * Resource/identity/owner-binding verifier. Cryptographic token and
 * KV validation remain the pinned provider's job through the required server
 * dependency. This module neither installs nor instantiates that provider.
 * No issuance, consent, token exchange, refresh, writes, fetches, logging or
 * cache. Production `/mcp` binds validateToken to the pinned provider.
 * A Dot token is accepted when its scope equals the scope stored for that
 * Bridge-issued grant, including an empty scope. Any other scope returns
 * the stored grant scope as insufficient_scope and must not authenticate a participant.
 */
export async function verifyParticipantOAuth(
  request: Request,
  deps: DotOAuthDependencies,
  expectedParticipant?: OAuthParticipant,
): Promise<OAuthParticipant | InsufficientDotScope | null> {
  const token = BEARER.exec(request.headers.get("Authorization") ?? "")?.[1];
  // Grok's namespace is exclusive, including malformed Grok-prefixed tokens.
  if (!token || token.startsWith("admrn_gb_")) return null;
  try {
    const resource = deps.resource;
    const url = new URL(resource);
    if (url.protocol !== "https:" || resource !== `${url.origin}/mcp`) throw new Error("internal_error");
    const validation = await deps.validateToken(resource, token);
    if (!object(validation)) return null;
    const client = oauthClient(validation.clientId);
    if (!client || (expectedParticipant !== undefined && client.participant !== expectedParticipant)
      || validation.audience !== resource
      || validation.userId !== client.participant
      || typeof validation.expiresAt !== "number" || !Number.isFinite(validation.expiresAt)
      || !object(validation.props) || Object.keys(validation.props).length !== 1
      || !Object.hasOwn(validation.props, "credential_id")
      || typeof validation.props.credential_id !== "string" || !validation.props.credential_id) return null;
    const scope = validation.scope;
    if (!stringList(scope)) return null;

    const now = deps.now ?? Date.now;
    const expiresAt = validation.expiresAt;
    // The provider's split API can return the exact expiry second. Match its
    // resource-server guard: equality is expired, without extending the TTL.
    if (!unexpired(expiresAt, now)) return null;
    const session = deps.db.withSession("first-primary");
    const [result] = await session.batch<{ participant: string; enabled: number }>([
      session.prepare(READ_PRINCIPAL).bind(validation.props.credential_id, client.participant),
    ]);
    if (!result?.success || !Array.isArray(result.results)) throw new Error("internal_error");
    // Recheck after asynchronous D1 access so a queued read cannot admit a
    // token that expired while resolving the current owner/credential state.
    if (result.results.length !== 1 || result.results[0].participant !== client.participant || !unexpired(expiresAt, now)) {
      return null;
    }
    const enabled = result.results[0].enabled;
    if (enabled !== 0 && enabled !== 1) return null;
    const grant = issuedGrant(token);
    if (!grant || grant.userId !== client.participant) return null;
    const stored = await lookup(() => deps.readGrantScope(grant.userId, grant.grantId));
    // Recheck after the grant-scope read so a token that expires during KV access is not admitted.
    if (!stringList(stored) || !unexpired(expiresAt, now)) return null;
    if (sameScope(scope, stored)) {
      if (enabled === 0) throw new ParticipantDisabled();
      return client.participant;
    }
    return { decision: "insufficient_scope", scope: [...stored] };
  } catch (error) {
    if (error instanceof DotAuthUnavailable || error instanceof ParticipantDisabled) throw error;
    // The adapter maps this to its fixed 500; never retain sensitive causes.
    throw new Error("internal_error");
  }
}

async function lookup<T>(read: () => Promise<T>): Promise<T> {
  try {
    return await read();
  } catch (error) {
    if (error instanceof DotAuthUnavailable) throw error;
    throw new DotAuthUnavailable();
  }
}

/** Compatibility entry point for callers that intentionally accept Dot only. */
export async function verifyDotOAuth(request: Request, deps: DotOAuthDependencies): Promise<"dot" | InsufficientDotScope | null> {
  const result = await verifyParticipantOAuth(request, deps, "dot");
  return result === "claude" ? null : result;
}
