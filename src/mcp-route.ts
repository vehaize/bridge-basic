/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Production /mcp. Transport checks stay in the adapter and run before this
 * principal lookup. A missing, invalid, expired, revoked, wrong-audience, or
 * unknown-client credential is 401. A valid disabled participant is temporarily
 * unavailable with 503 and Retry-After. A Dot scope that differs from the scope
 * stored for that Bridge-issued grant is 403. Neither reaches the lifecycle.
 */

import { DotAuthUnavailable, verifyParticipantOAuth, type InsufficientDotScope } from "./dot-oauth.ts";
import { verifyGrokBearer } from "./grok-bearer.ts";
import { ItemLifecycle, type Participant } from "./item-lifecycle.ts";
import { liveWritesEnabled } from "./live-switch.ts";
import { logInfo, logNonSuccess } from "./log.ts";
import { handleMcpRequest, McpForbidden } from "./mcp-adapter.ts";
import { canonicalOrigin, openAuthorizationServer, type BridgeEnv } from "./oauth-routes.ts";
import { enforceAuthenticatedLimit } from "./rate-limit.ts";
import { deliverWake } from "./wake.ts";

import { oauthParticipant } from "./participants.ts";

const GROK_PREFIX = "admrn_gb_";

type AuthReason = "missing_token" | "invalid_token" | "insufficient_scope" | "oauth_not_configured" | "origin_not_configured" | "storage_unavailable";

export function mcpChallenge(origin: string): string {
  return `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`;
}

function logAuth(reason: AuthReason): void {
  logInfo({ message: "bridge event", event: "auth.failed", reason });
}

function readingKv(kv: KVNamespace): KVNamespace {
  return new Proxy(kv, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver);
      if (property !== "get" || typeof value !== "function") return value;
      return async (...args: unknown[]) => {
        try {
          return await value.apply(target, args);
        } catch (error) {
          if (error instanceof DotAuthUnavailable) throw error;
          throw new DotAuthUnavailable();
        }
      };
    },
  });
}

function json(body: unknown, status: number): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

/**
 * Scope on the provider's KV grant record. A missing or malformed record is
 * not a grant. This read is not a revocation check. Revocation follows D1
 * participant_credential.revoked_at, which verifyParticipantOAuth reads on every call.
 */
async function readGrantScope(kv: KVNamespace, userId: string, grantId: string): Promise<string[] | null> {
  const client = oauthParticipant(userId);
  if (!client || !/^[A-Za-z0-9_-]{1,128}$/.test(grantId)) return null;
  const stored: unknown = await kv.get(`grant:${userId}:${grantId}`, { type: "json" });
  if (!record(stored) || stored.id !== grantId || stored.userId !== userId
    || stored.clientId !== client.clientId || !stringList(stored.scope)) {
    return null;
  }
  return stored.scope;
}

export async function handleMcpRoute(request: Request, env: BridgeEnv, ctx?: ExecutionContext): Promise<Response> {
  const origin = canonicalOrigin(env.BRIDGE_ORIGIN);
  if (!origin) {
    logAuth("origin_not_configured");
    return json({ error: "internal_error" }, 500);
  }
  if (new URL(request.url).origin !== origin) {
    const missing = json({ ok: false, error: "not_found" }, 404);
    await logNonSuccess("mcp.refused", missing);
    return missing;
  }
  const response = await handleMcpRequest(request, {
    lifecycle: new ItemLifecycle(env.DB, Date.now, (change) => {
      // No ctx means a direct test call. Production fetch always supplies one.
      // Do not start the delivery promise unless waitUntil will retain it.
      if (!ctx) return;
      ctx.waitUntil(deliverWake(env, change));
    }),
    unauthorizedChallenge: mcpChallenge(origin),
    getPrincipal: () => resolvePrincipal(request, env, `${origin}/mcp`),
    onAuthenticated: () => enforceAuthenticatedLimit(env, request.headers.get("Authorization") ?? ""),
    writesEnabled: liveWritesEnabled(env.LIVE_ENABLED),
  });
  await logNonSuccess("mcp.refused", response);
  return response;
}

async function resolvePrincipal(request: Request, env: BridgeEnv, resource: string): Promise<Participant | null> {
  const authorization = request.headers.get("Authorization");
  if (authorization === null) {
    logAuth("missing_token");
    return null;
  }
  // Grok's prefix is exclusive, including a malformed token. Never hand it to Dot.
  if (authorization.includes(GROK_PREFIX)) {
    const grok = await verifyGrokBearer(request, env.DB);
    if (grok !== "grok_bot") logAuth("invalid_token");
    return grok;
  }
  const opened = openAuthorizationServer(env);
  if (!opened || !env.OAUTH_KV || opened.resource !== resource) {
    logAuth("oauth_not_configured");
    throw new Error("internal_error");
  }
  const kv = readingKv(env.OAUTH_KV);
  let decision: Awaited<ReturnType<typeof verifyParticipantOAuth>>;
  try {
    decision = await verifyParticipantOAuth(request, {
      db: env.DB,
      resource,
      validateToken: (audience, token) => opened.server.validateToken(audience, token, { OAUTH_KV: kv }),
      readGrantScope: (userId, grantId) => readGrantScope(kv, userId, grantId),
    });
  } catch (error) {
    if (error instanceof DotAuthUnavailable) logAuth("storage_unavailable");
    throw error;
  }
  switch (decision) {
    case "dot":
    case "claude":
      return decision;
    case null:
      logAuth("invalid_token");
      return null;
    default:
      return denyScope(decision);
  }
}

function denyScope(decision: InsufficientDotScope): never {
  switch (decision.decision) {
    case "insufficient_scope":
      logAuth("insufficient_scope");
      throw new McpForbidden(decision.scope);
    default: {
      const neverDecision: never = decision.decision;
      return neverDecision;
    }
  }
}
