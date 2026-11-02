/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE = "@cloudflare/workers-oauth-provider";
const VERSION = "1.2.3";
const URL = "https://registry.npmjs.org/@cloudflare/workers-oauth-provider/-/workers-oauth-provider-1.2.3.tgz";
// Copied from the original provider tests and docs/implementation/oauth-provider-probe.md.
const SHA256 = "ac5ca026121e1ac0db9f8910359f0544130521f07050ef4bb3e8f9a04cd08291";
const ARCHIVE = "workers-oauth-provider-1.2.3.tgz";
const MAX_BYTES = 5 * 1024 * 1024;

async function lockedIntegrity(root) {
  const manifest = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const lock = JSON.parse(await readFile(join(root, "package-lock.json"), "utf8"));
  const entry = lock.packages?.[`node_modules/${PACKAGE}`];
  if (manifest.dependencies?.[PACKAGE] !== VERSION ||
      lock.packages?.[""]?.dependencies?.[PACKAGE] !== VERSION || entry?.version !== VERSION) {
    throw new Error("OAuth provider must be pinned to 1.2.3 in package.json and package-lock.json");
  }
  if (entry.resolved !== URL) throw new Error("OAuth provider lockfile URL must be the official pinned npm artifact");
  if (typeof entry.integrity !== "string" || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity)) {
    throw new Error("OAuth provider lockfile must contain a SHA-512 integrity value");
  }
  return entry.integrity;
}

function verify(bytes, integrity) {
  if (createHash("sha256").update(bytes).digest("hex") !== SHA256) {
    throw new Error("OAuth provider archive SHA-256 mismatch; refusing to use or replace it");
  }
  if (`sha512-${createHash("sha512").update(bytes).digest("base64")}` !== integrity) {
    throw new Error("OAuth provider archive does not match package-lock.json SHA-512 integrity");
  }
  return bytes;
}

// Tests extract only these verified bytes, never reopen an unchecked archive.
// This function is deliberately offline, including when the archive is absent.
export async function readProviderArchive(root = ROOT) {
  const integrity = await lockedIntegrity(root);
  return verify(await readFile(join(root, "receipts", ARCHIVE)), integrity);
}

export async function prepareProviderArchive({ root = ROOT, fetchArtifact = fetch } = {}) {
  // Check the lock before any network request or filesystem write.
  const integrity = await lockedIntegrity(root);
  const destination = join(root, "receipts", ARCHIVE);
  try {
    verify(await readFile(destination), integrity);
    return "verified cached OAuth provider 1.2.3 (SHA-256 and lockfile SHA-512)";
  } catch (error) {
    // A corrupt cache is an error, not permission to silently replace evidence.
    if (error.code !== "ENOENT") throw error;
  }

  const response = await fetchArtifact(URL, {
    redirect: "error", credentials: "omit", signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`OAuth provider download failed: HTTP ${response.status}`);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > MAX_BYTES) throw new Error("OAuth provider download exceeds 5 MiB");
    chunks.push(chunk);
  }
  const bytes = verify(Buffer.concat(chunks), integrity);
  const directory = dirname(destination);
  await mkdir(directory, { recursive: true });
  const scratch = await mkdtemp(join(directory, ".oauth-provider-"));
  try {
    const temporary = join(scratch, ARCHIVE);
    await writeFile(temporary, bytes, { flag: "wx" });
    await rename(temporary, destination);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
  return "downloaded and verified OAuth provider 1.2.3 (SHA-256 and lockfile SHA-512)";
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 2) throw new Error("usage: node scripts/oauth-provider-artifact.mjs");
    console.log(await prepareProviderArchive());
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
