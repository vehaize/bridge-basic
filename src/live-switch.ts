/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Operator kill switch. Only an unset value or the exact string "true" allows
 * writes. Every other string fails closed and refuses writes. This module does
 * not read or change item state, and it does not gate the retention cron.
 */

import { logInfo } from "./log.ts";

export const LIVE_DISABLED_REASON = "live_disabled";

/** Tools that stay available when writes are off. A recipient read can stamp delivered_at. */
export const LIVE_READ_TOOLS = ["list_items", "get_item"] as const;

/**
 * JSON-RPC methods that do not write. tools/call is not in this list: while
 * writes are off, a call is allowed only when its tool is in LIVE_READ_TOOLS.
 * Any other method is refused before its handler runs.
 */
export const LIVE_READ_METHODS = [
  "initialize",
  "ping",
  "tools/list",
  "notifications/initialized",
] as const;

const READ_TOOLS = new Set<string>(LIVE_READ_TOOLS);
const READ_METHODS = new Set<string>(LIVE_READ_METHODS);
const LOGGED_TOOL = /^[a-z][a-z0-9_]{0,63}$/;

export function liveWritesEnabled(value: string | undefined): boolean {
  return value === undefined || value === "true";
}

export function isLiveReadTool(name: string): boolean {
  return READ_TOOLS.has(name);
}

export function isLiveReadMethod(method: string): boolean {
  return READ_METHODS.has(method);
}

/** Bridge event with the route or tool name and the live_disabled reason. No body, token, code, or identity. */
export function logLiveDisabled(subject: { route: "owner_claim" | "authorize" | "token" } | { tool: string }): void {
  if ("route" in subject) {
    logInfo({
      message: "bridge event",
      event: "live.disabled",
      route: subject.route,
      reason: LIVE_DISABLED_REASON,
    });
    return;
  }
  logInfo({
    message: "bridge event",
    event: "live.disabled",
    tool: LOGGED_TOOL.test(subject.tool) ? subject.tool : "unnamed",
    reason: LIVE_DISABLED_REASON,
  });
}

export function liveDisabledResponse(): Response {
  return Response.json(
    { error: LIVE_DISABLED_REASON },
    { status: 403, headers: { "Cache-Control": "no-store" } },
  );
}
