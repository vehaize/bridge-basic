/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Daily retention. The cron schedule is RETENTION_CRON in src/provisional.ts
 * and wrangler.example.jsonc. This module does not call Wrangler or Cloudflare.
 */

import { pruneAuditRows, sweepExpiredItems } from "./item-lifecycle.ts";
import { logError, logInfo } from "./log.ts";

/**
 * Materialize expiry and purge items, then prune audit rows older than their
 * own horizon in a separate batch. Logs deleted-row counts. A storage failure
 * logs no SQL text. The returned count is deleted item rows.
 */
export async function runRetention(db: D1Database, nowMs = Date.now()): Promise<number> {
  let count: number;
  try {
    count = await sweepExpiredItems(db, nowMs);
    logInfo({ message: "bridge event", event: "retention.purged", count });
  } catch {
    logError({ message: "bridge event", event: "retention.purged", reason: "internal_error" });
    throw new Error("internal_error");
  }
  // Audit rows outlive items. A failed prune cannot roll back the item purge above.
  try {
    const audit = await pruneAuditRows(db, nowMs);
    logInfo({ message: "bridge event", event: "retention.audit_pruned", count: audit });
  } catch {
    logError({ message: "bridge event", event: "retention.audit_pruned", reason: "internal_error" });
  }
  return count;
}
