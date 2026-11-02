/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Optional hint to Grok Bot. Polling stays the source of truth.
 * One attempt, no outbox, no retry. The body is only type, item_id, and occurred_at.
 * `wrangler types` reads only the Wrangler config, so WAKE_SECRET_GROK_BOT is typed
 * by the caller and is not a var in wrangler.example.jsonc.
 */

import type { CommittedChange, Participant } from "./item-lifecycle.ts";
import { logError, logInfo } from "./log.ts";

export type WakeResult = "not_configured" | "sent" | "failed" | "no_secret";

export interface WakeEnv {
  DB: D1Database;
  WAKE_SECRET_GROK_BOT?: string;
}

export interface WakeDeps {
  fetch?: typeof fetch;
  now?: () => number;
}

const SECRET_PREFIX = "whsec_";
const TIMEOUT_MS = 5000;

function report(change: CommittedChange, result: WakeResult, status?: number): WakeResult {
  const event = wakeEvent(result);
  const fields = {
    message: "bridge event" as const,
    event,
    participant: change.participant,
    item_id: change.itemId,
    reason: result,
    ...(status === undefined ? {} : { status }),
  };
  switch (result) {
    case "sent":
    case "not_configured":
      logInfo(fields);
      break;
    case "failed":
    case "no_secret":
      logError(fields);
      break;
    default: {
      const neverResult: never = result;
      return neverResult;
    }
  }
  return result;
}

function wakeEvent(result: WakeResult): "wake.sent" | "wake.not_configured" | "wake.failed" {
  switch (result) {
    case "sent":
      return "wake.sent";
    case "not_configured":
      return "wake.not_configured";
    case "failed":
    case "no_secret":
      return "wake.failed";
    default: {
      const neverResult: never = result;
      return neverResult;
    }
  }
}

/** Standard base64 of exactly 32 bytes, after the whsec_ prefix. */
export function decodeWakeSecret(secret: string | undefined): Uint8Array | null {
  if (!secret || !secret.startsWith(SECRET_PREFIX)) return null;
  const encoded = secret.slice(SECRET_PREFIX.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) return null;
  let binary: string;
  try {
    binary = atob(encoded);
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return bytes.byteLength === 32 ? bytes : null;
}

function acceptable(value: string): URL | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username !== "" || url.password !== "") return null;
  // WHATWG URL drops a bare trailing ? or #, so search and hash stay empty.
  if (value.includes("?") || value.includes("#")) return null;
  if (url.search !== "" || url.hash !== "") return null;
  return url;
}

async function readWakeUrl(db: D1Database, participant: Participant): Promise<string | null> {
  const session = db.withSession("first-primary");
  const [result] = await session.batch<{ wake_url: string | null }>([
    session.prepare("SELECT wake_url FROM participant WHERE id = ?1 AND enabled = 1").bind(participant),
  ]);
  if (!result?.success || !Array.isArray(result.results)) throw new Error("unavailable");
  return result.results[0]?.wake_url ?? null;
}

async function sign(secret: Uint8Array, content: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(content));
  let binary = "";
  for (const byte of new Uint8Array(mac)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Deliver one wake. Never logs the URL, the secret, or item text. */
export async function deliverWake(env: WakeEnv, change: CommittedChange, deps: WakeDeps = {}): Promise<WakeResult> {
  switch (change.participant) {
    case "grok_bot":
      break;
    case "dot":
    case "claude":
      return report(change, "not_configured");
    default: {
      const neverParticipant: never = change.participant;
      return neverParticipant;
    }
  }
  let stored: string | null;
  try {
    stored = await readWakeUrl(env.DB, change.participant);
  } catch {
    return report(change, "failed");
  }
  if (stored === null || stored.trim() === "") return report(change, "not_configured");
  const secret = decodeWakeSecret(env.WAKE_SECRET_GROK_BOT);
  if (!secret) return report(change, "no_secret");
  const url = acceptable(stored.trim());
  if (!url) return report(change, "failed");

  const body = JSON.stringify({ type: change.type, item_id: change.itemId, occurred_at: change.occurredAt });
  const fetchImpl = deps.fetch ?? fetch;
  let response: Response;
  try {
    const id = `msg_${crypto.randomUUID()}`;
    const timestamp = String(Math.floor((deps.now ?? Date.now)() / 1000));
    const signature = await sign(secret, `${id}.${timestamp}.${body}`);
    response = await fetchImpl(url, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: {
        "content-type": "application/json",
        "webhook-id": id,
        "webhook-timestamp": timestamp,
        "webhook-signature": `v1,${signature}`,
      },
      body,
    });
  } catch {
    return report(change, "failed");
  }
  if (response.body) {
    try {
      await response.body.cancel();
    } catch {
      // Discarding the body is enough. The status is already known.
    }
  }
  if (response.status >= 200 && response.status < 300) return report(change, "sent", response.status);
  return report(change, "failed", response.status);
}
