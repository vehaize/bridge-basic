/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { OwnerClaimEnv } from "../src/owner-claim.ts";
import { routeRequest } from "../src/router.ts";

// Any read of the owner email, the bootstrap secret, or D1 throws.
const untouchedEnv = new Proxy({} as OwnerClaimEnv, {
  get(_target, key) {
    throw new Error(`read env.${String(key)}`);
  },
});

const VERSION_OR_ENV_KEY =
  /(^|_)(version|env|environment)(_|$)/i;

function assertNoVersionOrEnv(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      assertNoVersionOrEnv(item);
    }
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      assert.equal(VERSION_OR_ENV_KEY.test(key), false, key);
      assertNoVersionOrEnv(child);
    }
  }
}

const REQUIRED_PLACEHOLDERS = [
  "<YOUR_ACCOUNT_ID>",
  "<YOUR_D1_DATABASE_ID>",
  "<YOUR_KV_NAMESPACE_ID>",
  "<YOUR_OAUTH_KV_NAMESPACE_ID>",
  "<YOUR_DOMAIN>",
  "<OWNER_EMAIL>",
] as const;

describe("health", () => {
  it("serves GET /health without reading config or D1", async () => {
    const health = await routeRequest(
      new Request("https://bridge.invalid/health"),
      untouchedEnv,
    );
    assert.equal(health.status, 200);
    assert.equal(
      health.headers.get("content-type")?.startsWith("application/json"),
      true,
    );
    const body: unknown = await health.json();
    assert.deepEqual(body, {
      ok: true,
      service: "admrn-bridge",
      phase: "v0.1-candidate",
      status: "v0.1-candidate",
      mvp: "grok-bot-dot",
    });
    assertNoVersionOrEnv(body);

    const missing = await routeRequest(
      new Request("https://bridge.invalid/other", { method: "POST" }),
      untouchedEnv,
    );
    assert.equal(missing.status, 404);
    assert.deepEqual(await missing.json(), { ok: false, error: "not_found" });
  });

  it("keeps operator identifiers as placeholders in the Wrangler template", () => {
    const templatePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../wrangler.example.jsonc",
    );
    const template = readFileSync(templatePath, "utf8");
    for (const placeholder of REQUIRED_PLACEHOLDERS) {
      assert.equal(template.includes(placeholder), true, placeholder);
    }
  });
});
