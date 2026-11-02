/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { prepareProviderArchive, readProviderArchive } from "../scripts/oauth-provider-artifact.mjs";

// test:provider prepares this once. All failure injections below are offline and
// use disposable copies; neither the repository cache nor its lockfile is edited.
const archive = await readProviderArchive();
const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const lock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
const name = "@cloudflare/workers-oauth-provider";
const packageKey = `node_modules/${name}`;
const archiveName = "workers-oauth-provider-1.2.3.tgz";

async function fixture(t, mutate = () => {}) {
  const root = await mkdtemp(join(tmpdir(), "oauth-provider-artifact-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const files = { manifest: structuredClone(manifest), lock: structuredClone(lock) };
  mutate(files);
  await writeFile(join(root, "package.json"), JSON.stringify(files.manifest));
  await writeFile(join(root, "package-lock.json"), JSON.stringify(files.lock));
  return root;
}

function offline() { assert.fail("unexpected network request"); }

test("clean checkout downloads only the pinned public URL and verifies before caching", async (t) => {
  const root = await fixture(t);
  let calls = 0;
  await prepareProviderArchive({ root, fetchArtifact: async (url, options) => {
    calls++;
    assert.equal(url, lock.packages[packageKey].resolved);
    assert.equal(options.redirect, "error");
    assert.equal(options.credentials, "omit");
    assert.ok(options.signal instanceof AbortSignal);
    return new Response(archive);
  } });
  assert.equal(calls, 1);
  assert.deepEqual(await readProviderArchive(root), archive);
  assert.deepEqual(await readdir(join(root, "receipts")), [archiveName]);
  await prepareProviderArchive({ root, fetchArtifact: offline });
});

for (const [label, mutate, message] of [
  ["manifest version drift", ({ manifest }) => { manifest.dependencies[name] = "^1.2.3"; }, /pinned to 1\.2\.3/],
  ["root lock version drift", ({ lock }) => { lock.packages[""].dependencies[name] = "1.2.4"; }, /pinned to 1\.2\.3/],
  ["package lock version drift", ({ lock }) => { lock.packages[packageKey].version = "1.2.4"; }, /pinned to 1\.2\.3/],
  ["missing provider lock", ({ lock }) => { delete lock.packages[packageKey]; }, /pinned to 1\.2\.3/],
  ["untrusted URL", ({ lock }) => { lock.packages[packageKey].resolved = "https://untrusted.invalid/provider.tgz"; }, /official pinned npm artifact/],
  ["missing integrity", ({ lock }) => { delete lock.packages[packageKey].integrity; }, /SHA-512 integrity value/],
  ["weaker integrity", ({ lock }) => { lock.packages[packageKey].integrity = "sha1-synthetic"; }, /SHA-512 integrity value/],
]) test(`${label} fails before downloading or writing`, async (t) => {
  const root = await fixture(t, mutate);
  await assert.rejects(prepareProviderArchive({ root, fetchArtifact: offline }), message);
  await assert.rejects(readFile(join(root, "receipts", archiveName)), { code: "ENOENT" });
});

test("valid SHA-256 cannot bypass a mismatched lockfile SHA-512", async (t) => {
  const root = await fixture(t, ({ lock }) => {
    lock.packages[packageKey].integrity = `sha512-${Buffer.alloc(64).toString("base64")}`;
  });
  await assert.rejects(prepareProviderArchive({ root, fetchArtifact: async () => new Response(archive) }), /package-lock\.json SHA-512/);
  await assert.rejects(readFile(join(root, "receipts", archiveName)), { code: "ENOENT" });
  await mkdir(join(root, "receipts"));
  await writeFile(join(root, "receipts", archiveName), archive);
  await assert.rejects(readProviderArchive(root), /package-lock\.json SHA-512/);
  await assert.rejects(prepareProviderArchive({ root, fetchArtifact: offline }), /package-lock\.json SHA-512/);
});

test("tampered cached bytes fail without a replacement download", async (t) => {
  const root = await fixture(t);
  const corrupt = Buffer.from(archive);
  corrupt[corrupt.length - 1] ^= 1;
  await mkdir(join(root, "receipts"));
  await writeFile(join(root, "receipts", archiveName), corrupt);
  await assert.rejects(prepareProviderArchive({ root, fetchArtifact: offline }), /SHA-256 mismatch/);
  await assert.rejects(readProviderArchive(root), /SHA-256 mismatch/);
  assert.deepEqual(await readFile(join(root, "receipts", archiveName)), corrupt);
});

for (const [label, fetchArtifact, message] of [
  ["HTTP error", async () => new Response("unavailable", { status: 503 }), /HTTP 503/],
  ["network or redirect rejection", async () => { throw new Error("synthetic fetch failure"); }, /synthetic fetch failure/],
  ["truncated download", async () => new Response(archive.subarray(0, 16)), /SHA-256 mismatch/],
  ["oversized download", async () => new Response(new Uint8Array(5 * 1024 * 1024 + 1)), /exceeds 5 MiB/],
]) test(`${label} leaves no usable archive`, async (t) => {
  const root = await fixture(t);
  await assert.rejects(prepareProviderArchive({ root, fetchArtifact }), message);
  await assert.rejects(readFile(join(root, "receipts", archiveName)), { code: "ENOENT" });
});

test("direct test reads do not download when the cache is missing", async (t) => {
  const root = await fixture(t);
  await assert.rejects(readProviderArchive(root), { code: "ENOENT" });
});
