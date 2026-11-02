/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import type { RateLimitBinding } from "../src/rate-limit.ts";

export function permissiveRateLimits(limit?: RateLimitBinding["limit"]): {
  UNAUTHENTICATED_RATE_LIMIT: RateLimitBinding;
  AUTHENTICATED_RATE_LIMIT: RateLimitBinding;
} {
  const binding: RateLimitBinding = { limit: limit ?? (async () => ({ success: true })) };
  return { UNAUTHENTICATED_RATE_LIMIT: binding, AUTHENTICATED_RATE_LIMIT: { limit: binding.limit } };
}
