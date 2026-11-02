/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Node stand-in for the Workers entrypoint base class. The OAuth provider
 * imports it at load time. Production resolves the real `cloudflare:workers`
 * module; this file is only registered by the test runner.
 */
export class WorkerEntrypoint {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
}
