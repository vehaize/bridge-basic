/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Owner-approved defaults, 2026-10-25. Each decision is one named constant.
 * Later slices import these. Do not copy the numbers into a second constant.
 */

/** Item deadline used when open_item omits deadline_minutes. 6 hours. */
export const ITEM_DEADLINE_DEFAULT_MINUTES = 360;

/** Largest deadline_minutes open_item accepts. 24 hours. */
export const ITEM_DEADLINE_MAX_MINUTES = 1440;

/** Smallest deadline_minutes open_item accepts. */
export const ITEM_DEADLINE_MIN_MINUTES = 5;

/**
 * An open or claimed item is expiring_soon when its deadline is at or inside
 * this many minutes. Computed on read. Not stored. Not one of the four
 * approved decisions.
 */
export const ITEM_EXPIRING_SOON_MINUTES = 60;

/** Daily retention deletes a finished row this many days after its last change. */
export const RETENTION_PURGE_DAYS = 30;

/**
 * Owner decision, 2026-10-26. Audit rows are kept longer than items. Daily
 * retention deletes an item_audit row only when it is older than this many
 * days, the same horizon the migration 0006 delete trigger enforces.
 */
export const AUDIT_RETENTION_DAYS = 90;

/** One daily Cron Trigger. Workers Free allows five triggers for each account. */
export const RETENTION_CRON = "0 0 * * *";

/** Requests per period for one route and one CF-Connecting-IP before a credential is verified. */
export const UNAUTHENTICATED_RATE_LIMIT = 60;

/** Requests per period for one verified credential. */
export const AUTHENTICATED_RATE_LIMIT = 120;

/** Shared period, in seconds, for both rate-limit bindings. */
export const RATE_LIMIT_PERIOD_SECONDS = 60;

/**
 * Logged when a limited route has no rate-limit binding, the binding cannot
 * be called, or the client address required to key the unauthenticated limit
 * is missing. The HTTP status is 503.
 */
export const RATE_LIMIT_UNAVAILABLE_REASON = "rate_limit_unavailable";

/** Recipient decline is deferred. item.state is a CHECK, so this is not a column add. */
export const RECIPIENT_DECLINE_ENABLED = false;
