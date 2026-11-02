/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { logError } from "./log.ts";
import { runRetention } from "./retention.ts";
import { routeRequest } from "./router.ts";

export default {
  async fetch(request, env, ctx): Promise<Response> {
    try {
      // Handlers schedule a wake on this ctx. Call waitUntil on the object itself.
      return await routeRequest(request, env, ctx);
    } catch {
      logError({ message: "request failed", reason: "internal_error" });
      return Response.json({ ok: false, error: "internal_error" }, { status: 500 });
    }
  },
  async scheduled(_controller, env, _ctx): Promise<void> {
    // Does not read LIVE_ENABLED. Expiry and the 30-day purge still run when writes are off.
    await runRetention(env.DB);
  },
} satisfies ExportedHandler<Env>;
