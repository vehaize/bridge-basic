/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

type LogValue = string | number | boolean;

const SAFE_REASON = /^[a-z0-9_-]{1,80}$/;

export function logInfo(fields: Record<string, LogValue>): void {
  console.log(JSON.stringify(fields));
}

export function logError(fields: Record<string, LogValue>): void {
  console.error(JSON.stringify(fields));
}

/** One fixed reason for a non-2xx response. The body is not logged. */
export async function logNonSuccess(event: string, response: Response): Promise<void> {
  if (response.status >= 200 && response.status < 300) return;
  let reason = "unspecified";
  try {
    const body: unknown = await response.clone().json();
    if (typeof body === "object" && body !== null && !Array.isArray(body)) {
      const error = (body as { error?: unknown }).error;
      if (typeof error === "string" && SAFE_REASON.test(error)) reason = error;
    }
  } catch {
    reason = "unspecified";
  }
  const fields = { message: "bridge event", event, reason, status: response.status };
  if (response.status >= 500) logError(fields);
  else logInfo(fields);
}
