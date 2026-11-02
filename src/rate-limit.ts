/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Workers Rate Limiting bindings. The binding is free and has no per-call charge.
 * simple.limit and simple.period in wrangler.example.jsonc are the named constants
 * in src/provisional.ts. This module does not cap CPU time.
 */

import { logError, logInfo } from "./log.ts";
import { RATE_LIMIT_PERIOD_SECONDS, RATE_LIMIT_UNAVAILABLE_REASON } from "./provisional.ts";

export interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface RateLimitEnv {
  UNAUTHENTICATED_RATE_LIMIT?: RateLimitBinding;
  AUTHENTICATED_RATE_LIMIT?: RateLimitBinding;
}

/** Routes that spend an address bucket. Each one is a separate key from the others. */
export type UnauthenticatedRoute = "authorize" | "token" | "owner_claim" | "mcp";

function json(body: unknown, status: number, extra?: HeadersInit): Response {
  const headers = new Headers(extra);
  headers.set("Cache-Control", "no-store");
  return Response.json(body, { status, headers });
}

function unavailable(): Response {
  logError({
    message: "bridge event",
    event: "rate_limit.unavailable",
    reason: RATE_LIMIT_UNAVAILABLE_REASON,
    status: 503,
  });
  return json({ ok: false, error: RATE_LIMIT_UNAVAILABLE_REASON }, 503);
}

function limited(): Response {
  logInfo({ message: "bridge event", event: "rate_limited", reason: "rate_limited", status: 429 });
  return json({ error: "rate_limited" }, 429, { "Retry-After": String(RATE_LIMIT_PERIOD_SECONDS) });
}

function outcome(value: unknown): value is { success: boolean } {
  return typeof value === "object" && value !== null && typeof (value as { success?: unknown }).success === "boolean";
}

async function take(limiter: RateLimitBinding | undefined, key: string): Promise<Response | null> {
  if (!limiter || typeof limiter.limit !== "function") return unavailable();
  let result: unknown;
  try {
    result = await limiter.limit({ key });
  } catch {
    return unavailable();
  }
  if (!outcome(result)) return unavailable();
  return result.success ? null : limited();
}

/**
 * Before auth. The key is the route plus CF-Connecting-IP, so a full /mcp
 * bucket does not lock /authorize, /token, or /owner/claim. A missing address
 * cannot be limited, so it is refused.
 */
export async function enforceUnauthenticatedLimit(
  request: Request,
  env: RateLimitEnv,
  route: UnauthenticatedRoute,
): Promise<Response | null> {
  const ip = request.headers.get("CF-Connecting-IP")?.trim();
  if (!ip) return unavailable();
  return take(env.UNAUTHENTICATED_RATE_LIMIT, `${route}:ip:${ip}`);
}

/**
 * Scheme case and separator whitespace match the verifiers. The capture is the
 * token bytes, so `bearer X`, `Bearer  X`, and `Bearer X ` are one credential.
 */
const BEARER_TOKEN = /^bearer[ \t]+([^\s,]+)$/i;

function parsedBearerToken(authorization: string): string | null {
  return BEARER_TOKEN.exec(authorization.trim())?.[1] ?? null;
}

/** After a credential is verified. The key is the hash of the parsed token, so the header text is not the bucket and is not logged. */
export async function enforceAuthenticatedLimit(env: RateLimitEnv, authorization: string): Promise<Response | null> {
  const token = parsedBearerToken(authorization);
  if (!token) return unavailable();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const key = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return take(env.AUTHENTICATED_RATE_LIMIT, `credential:${key}`);
}
