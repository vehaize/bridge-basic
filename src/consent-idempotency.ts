/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * How long a spent Connect code may replay its redirect. D1 stores that
 * redirect on the spent row. Nothing reads a second copy back from KV.
 */

/** A repeat of the same challenge and state is accepted for this long after the spend. */
export const CONNECT_RESULT_TTL_SECONDS = 120;
