/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function markdownUnder(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...markdownUnder(path));
    } else if (entry.isFile() && entry.name.endsWith(".md")) {
      found.push(path);
    }
  }
  return found;
}

function timeTravelCommands(text: string): string[] {
  const lines = text.split("\n");
  const commands: string[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (!/\bwrangler\s+d1\s+time-travel\b/.test(line)) continue;
    const parts = [line];
    while (/\\\s*$/.test(parts[parts.length - 1] ?? "") && index + 1 < lines.length) {
      index += 1;
      parts.push(lines[index] ?? "");
    }
    commands.push(parts.join("\n"));
  }
  return commands;
}

describe("documented wrangler d1 time-travel commands", () => {
  it("does not pass --remote", () => {
    const files = [
      resolve(root, "README.md"),
      resolve(root, "CHANGELOG.md"),
      ...markdownUnder(resolve(root, "docs")),
      ...markdownUnder(resolve(root, "templates")),
    ];
    const commands = files.flatMap((file) =>
      timeTravelCommands(readFileSync(file, "utf8")).map((command) => ({
        file: relative(root, file),
        command,
      })),
    );
    const names: string[] = [];
    for (const { file, command } of commands) {
      const match = /\bwrangler\s+d1\s+time-travel\s+(info|restore)\b/.exec(command);
      assert.ok(match, `${file} documents an unknown time-travel command:\n${command}`);
      names.push(match[1] ?? "");
      assert.equal(command.includes("--remote"), false, `${file} passes --remote:\n${command}`);
    }
    assert.equal(names.includes("info"), true);
    assert.equal(names.includes("restore"), true);
  });

  it("follows the section 4 restore order", () => {
    const text = readFileSync(resolve(root, "docs/upgrade-and-recovery.md"), "utf8");
    const sectionStart = text.indexOf("## 4. Time Travel restore");
    const sectionEnd = text.indexOf("## 5. Emergency stop");
    assert.ok(sectionStart >= 0, "missing Time Travel restore section");
    assert.ok(sectionEnd > sectionStart, "missing Emergency stop section");
    const section = text.slice(sectionStart, sectionEnd);
    const markers: Array<[string, number]> = [
      ["BOOTSTRAP_SECRET removal", section.indexOf("wrangler secret delete BOOTSTRAP_SECRET")],
      ["LIVE_ENABLED false", section.indexOf('"LIVE_ENABLED": "false"')],
      ["custom domain detach", section.indexOf('"enabled": false')],
      ["current bookmark", section.search(/\bwrangler\s+d1\s+time-travel\s+info\b/)],
      ["time-travel restore", section.search(/\bwrangler\s+d1\s+time-travel\s+restore\b/)],
      ["revocation check", section.indexOf("active_credentials")],
      ["custom domain re-attach", section.indexOf('"enabled": true')],
      ["LIVE_ENABLED re-enable", section.indexOf('"LIVE_ENABLED": "true"')],
      ["writes-on check", section.indexOf("bootstrap_secret_required")],
      ["fresh owner bootstrap", section.indexOf("fresh owner bootstrap")],
    ];
    let previous = -1;
    for (const [name, at] of markers) {
      assert.ok(at >= 0, `missing ${name}`);
      assert.ok(at > previous, `${name} is out of order`);
      previous = at;
    }
    const restoreAt = markers[4][1];
    const reattachAt = markers[6][1];
    const reenableAt = markers[7][1];
    const devShutdown = section.search(/"workers_dev": false,\n\s*"preview_urls": false\n/);
    const devRestore = section.indexOf('"workers_dev": true');
    assert.ok(devShutdown >= 0, "missing workers_dev false shutdown");
    assert.ok(devRestore >= 0, "missing workers_dev true re-enable");
    assert.ok(devShutdown < restoreAt, "workers_dev false shutdown must precede the restore");
    assert.ok(devRestore > restoreAt, "workers_dev true re-enable must follow the restore");
    assert.ok(devRestore < reenableAt, "workers_dev true re-enable must precede turning writes on");
    assert.ok(
      section.includes("https://developers.cloudflare.com/workers/configuration/routing/workers-dev/"),
      "section 4 must cite the workers.dev docs",
    );
    assert.ok(
      section.includes("https://developers.cloudflare.com/workers/wrangler/configuration/"),
      "section 4 must cite the Wrangler configuration docs",
    );
    assert.ok(section.includes("Settings > Domains & Routes"), "section 4 must name the workers.dev dashboard path");
    const healthNeedle = '"$BRIDGE_ORIGIN/health"';
    const healthAts: number[] = [];
    for (let from = 0; from < section.length;) {
      const at = section.indexOf(healthNeedle, from);
      if (at < 0) break;
      healthAts.push(at);
      from = at + healthNeedle.length;
    }
    assert.ok(healthAts.length >= 1, "missing /health check");
    assert.ok(healthAts.every((at) => at > restoreAt), "/health must be verified after the restore");
    assert.ok(healthAts.some((at) => at > devRestore), "/health must be verified after workers_dev is re-enabled");
    assert.ok(healthAts.some((at) => at > reattachAt), "/health must be verified after the custom domain is re-attached");
    assert.ok(healthAts.every((at) => at < reenableAt), "/health must be verified before writes are turned back on");
    const fileDeleteAt = text.indexOf("wrangler secret delete BOOTSTRAP_SECRET");
    const fileRestoreAt = text.search(/\bwrangler\s+d1\s+time-travel\s+restore\b/);
    assert.ok(fileDeleteAt >= 0);
    assert.ok(fileRestoreAt >= 0);
    assert.ok(fileDeleteAt < fileRestoreAt, "BOOTSTRAP_SECRET removal must come before the time-travel restore line");
  });

  it("requires rate-limit namespace_id values to be distinct positive integer strings", () => {
    const template = readFileSync(resolve(root, "wrangler.example.jsonc"), "utf8");
    const install = readFileSync(resolve(root, "docs/install.md"), "utf8");
    const testInstance = readFileSync(resolve(root, "docs/test-instance.md"), "utf8");
    const ids = [...template.matchAll(/"namespace_id": "([^"]+)"/g)].map((match) => match[1] ?? "");
    assert.deepEqual(ids, ["1001", "1002"]);
    for (const id of ids) {
      assert.match(id, /^[1-9][0-9]*$/);
    }
    assert.equal(new Set(ids).size, ids.length);
    const constraint = /positive integer[\s\S]{0,180}hex ids? Cloudflare issues/;
    assert.match(template, constraint);
    assert.match(install, constraint);
    assert.match(testInstance, constraint);
    for (const text of [template, install, testInstance]) {
      assert.equal(text.includes("<YOUR_UNAUTHENTICATED_RATE_LIMIT_NAMESPACE_ID>"), false);
      assert.equal(text.includes("<YOUR_AUTHENTICATED_RATE_LIMIT_NAMESPACE_ID>"), false);
    }
  });

  it("names both D1 Time Travel windows and uses the applicable window in backup and restore", () => {
    const upgrade = readFileSync(resolve(root, "docs/upgrade-and-recovery.md"), "utf8");
    const backup = sliceBetween(upgrade, "## 1. Backup before an upgrade or a restore", "\n## 2. Upgrade");
    const restore = sliceBetween(upgrade, "## 4. Time Travel restore", "\n## 5. Emergency stop");
    const bothWindows = /30 days on Workers Paid and 7 days on Workers Free/;
    for (const section of [backup, restore]) {
      assert.match(section, bothWindows);
      assert.match(section, /applicable window/);
      assert.equal(/\blast 30 days\b/.test(section), false);
      assert.equal(/older than 30 days/.test(section), false);
    }
    for (const [file, text] of [
      ["docs/install.md", readFileSync(resolve(root, "docs/install.md"), "utf8")],
      ["docs/test-instance.md", readFileSync(resolve(root, "docs/test-instance.md"), "utf8")],
    ] as const) {
      assert.equal(/\blast 30 days\b/.test(text), false, `${file} states a flat 30-day Time Travel window`);
    }
  });
});

type ReconcileDoc = {
  file: string;
  config: string;
};

type EnvelopeObjects = {
  auditIndexes: string[];
  triggers: string[];
};

function namedCreates(sql: string, pattern: RegExp): string[] {
  const names: string[] = [];
  for (const match of sql.matchAll(pattern)) {
    const name = match[1];
    if (name) names.push(name);
  }
  return names;
}

function authorityEnvelopeObjects(sql: string): EnvelopeObjects {
  return {
    auditIndexes: namedCreates(sql, /^CREATE INDEX (item_audit_\S+)/gm),
    triggers: namedCreates(sql, /^CREATE TRIGGER (\S+)/gm),
  };
}

function sliceBetween(text: string, start: string, end: string): string {
  const from = text.indexOf(start);
  assert.ok(from >= 0, `missing ${start}`);
  const to = text.indexOf(end, from + start.length);
  assert.ok(to > from, `missing ${end}`);
  return text.slice(from, to);
}

function reconcileGaps(section: string, doc: ReconcileDoc, objects: EnvelopeObjects): string[] {
  const gaps: string[] = [];
  const ban = "do not run `migrations apply`";
  const baseline = section.indexOf("'0005_item_receipt.sql'");
  const banAt = section.indexOf(ban);
  if (banAt < 0 || baseline < 0 || banAt > baseline) {
    gaps.push(`${doc.file} must warn not to run migrations apply before the baseline is recorded`);
  } else if (!section.includes("until the baseline rows below are recorded")) {
    gaps.push(`${doc.file} must limit the migrations apply ban to the time before the baseline is recorded`);
  }
  if (baseline >= 0 && section.indexOf(ban, baseline + 1) >= 0) {
    gaps.push(`${doc.file} must not keep the migrations apply ban after the baseline is recorded`);
  }
  const applyCommand = `wrangler d1 migrations apply DB --remote --config ${doc.config}\n`;
  const applyAt = section.indexOf(applyCommand);
  const emptyAt = section.indexOf("No migrations to apply!");
  if (applyAt < 0 || emptyAt < applyAt) {
    gaps.push(`${doc.file} requires an empty pending list before it tells the operator to apply the remaining migrations`);
  }
  const probes = [
    "name = 'item_audit'",
    "name = 'item_audit_head'",
    "name = 'envelope_json'",
    "name = 'envelope_sha256'",
    "pragma_table_info('item')",
    "sqlite_master",
    "SELECT id, seq FROM item_audit_head",
    "the same way as the baseline",
    "file added after `0006_authority_envelope.sql`",
    "baseline rows mean only the remaining files run",
  ];
  for (const probe of probes) {
    if (!section.includes(probe)) gaps.push(`${doc.file} is missing ${probe}`);
  }
  if (objects.auditIndexes.length === 0 || objects.triggers.length === 0) {
    gaps.push("0006 object inventory is empty");
  }
  const counted = [
    "`audit_indexes` is `" + String(objects.auditIndexes.length) + "`",
    "`triggers` is `" + String(objects.triggers.length) + "`",
  ];
  for (const phrase of counted) {
    if (!section.includes(phrase)) gaps.push(`${doc.file} is missing ${phrase}`);
  }
  for (const name of [...objects.auditIndexes, ...objects.triggers]) {
    if (!section.includes(`'${name}'`)) gaps.push(`${doc.file} omits 0006 object ${name}`);
  }
  if (/0006 is the last/i.test(section) || /last migration/i.test(section)) {
    gaps.push(`${doc.file} must not treat 0006 as the last migration`);
  }
  return gaps;
}

describe("execute --file migration reconcile", () => {
  const objects = authorityEnvelopeObjects(readFileSync(join(root, "migrations/0006_authority_envelope.sql"), "utf8"));

  it("rejects a reconcile that requires an empty pending list before remaining migrations are applied", () => {
    const stale = [
      "do not run `migrations apply` until the baseline rows below are recorded.",
      "INSERT INTO d1_migrations (name) VALUES ('0001_owner_lock.sql'), ('0005_item_receipt.sql');",
      "The list must print `No migrations to apply!`.",
    ].join("\n");
    const gaps = reconcileGaps(stale, { file: "sample.md", config: "wrangler.jsonc" }, objects);
    assert.equal(gaps.some((gap) => gap.includes("empty pending list")), true);
    const applied = stale.replace(
      "The list must print `No migrations to apply!`.",
      "wrangler d1 migrations apply DB --remote --config wrangler.jsonc\nThe list must print `No migrations to apply!`.",
    );
    const remaining = reconcileGaps(applied, { file: "sample.md", config: "wrangler.jsonc" }, objects);
    assert.equal(remaining.some((gap) => gap.includes("empty pending list")), false);
  });

  it("applies remaining migrations after the baseline before it requires an empty pending list", () => {
    const install = readFileSync(resolve(root, "docs/install.md"), "utf8");
    const installSection = sliceBetween(
      install,
      "### A database that was loaded with `d1 execute --file`",
      "\n## 5. ",
    );
    assert.deepEqual(
      reconcileGaps(installSection, { file: "docs/install.md", config: "wrangler.jsonc" }, objects),
      [],
    );
    const testInstance = readFileSync(resolve(root, "docs/test-instance.md"), "utf8");
    const testSection = sliceBetween(
      testInstance,
      "If this test database already received",
      "\n## 4. ",
    );
    assert.deepEqual(
      reconcileGaps(testSection, { file: "docs/test-instance.md", config: "wrangler.test.jsonc" }, objects),
      [],
    );
  });

  it("checks upgrade-and-recovery when that runbook carries the baseline reconcile", () => {
    const upgrade = readFileSync(resolve(root, "docs/upgrade-and-recovery.md"), "utf8");
    const marker = "INSERT INTO d1_migrations (name) VALUES ('0001_owner_lock.sql')";
    if (upgrade.includes(marker)) {
      const afterBaseline = upgrade.slice(upgrade.indexOf(marker));
      const applyAt = afterBaseline.search(/wrangler d1 migrations apply\b/);
      const emptyAt = afterBaseline.indexOf("No migrations to apply!");
      assert.ok(
        applyAt >= 0 && emptyAt > applyAt,
        "docs/upgrade-and-recovery.md requires an empty pending list before it tells the operator to apply the remaining migrations",
      );
      return;
    }
    assert.match(upgrade, /\[docs\/install\.md\]\(install\.md\) section 4/);
  });
});
