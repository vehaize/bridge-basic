/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

describe("test instance runbook", () => {
  it("reads the private origin at runtime and keeps tracked examples anonymized", () => {
    const runbook = readFileSync(resolve(root, "docs/test-instance.md"), "utf8");
    const example = readFileSync(resolve(root, "wrangler.example.jsonc"), "utf8");
    for (const text of [runbook, example]) {
      const hosts = [...text.matchAll(/\bbridge-test\.[A-Za-z0-9.-]+/g)].map((match) => match[0]);
      assert.ok(hosts.length > 0);
      assert.ok(hosts.every((host) => host === "bridge-test.example.invalid"));
    }
    assert.equal(runbook.includes("https://bridge-test.example.invalid/"), false);
    assert.match(runbook, /"BRIDGE_ORIGIN": "https:\/\/bridge-test\.example\.invalid"/);
    assert.match(example, /bridge-test\.example\.invalid/);
    assert.match(runbook, /BRIDGE_ORIGIN="\$\(/);
    assert.match(runbook, /test -n "\$BRIDGE_ORIGIN"/);
    assert.match(runbook, /\*example\.invalid\*/);
    assert.match(runbook, /Build the connector URL from `\$BRIDGE_ORIGIN`/);
    assert.equal(runbook.match(/"\$BRIDGE_ORIGIN\//g)?.length, 12);
    assert.equal(example.includes("https://<YOUR_DOMAIN>"), true);
    assert.equal(example.includes("<YOUR_ACCOUNT_ID>"), true);
    assert.match(example, /enable_request_signal/);
    assert.match(runbook, /enable_request_signal/);
    assert.match(runbook, /disconnect cleanup does not run/);
  });

  it("reloads the Grok token in a new shell and requires a fresh idempotency key", () => {
    const runbook = readFileSync(resolve(root, "docs/test-instance.md"), "utf8");
    const smoke = runbook.slice(runbook.indexOf("Authenticated smoke"));
    assert.match(smoke, /grok_token="\$HOME\/grok-token"/);
    assert.match(smoke, /Could not read a Grok token from \$HOME\/grok-token\. Stop\./);
    assert.match(smoke, /unset token_line/);
    assert.equal(smoke.includes("echo \"$token_line\""), false);
    assert.equal(smoke.includes("echo \"$grok_token\""), false);
    assert.equal(smoke.includes("printf '%s\\n' \"$token_line\""), false);
    assert.equal(runbook.includes("req_testinstance01"), false);
    assert.match(runbook, /\^req_\[A-Za-z0-9_-\]\{8,64\}\$/);
    assert.match(runbook, /only to retry this open/);
    assert.match(runbook, /later independent run needs a new key/);
  });
});
