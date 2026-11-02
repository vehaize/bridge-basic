/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Local operator command. It writes a SQL file and, on issue, prints the new
 * Grok token once on stdout. It does not apply the file, call Wrangler, or
 * contact Cloudflare. The operator applies the file with:
 * wrangler d1 execute admrn-bridge --remote --file <file>
 * D1 runs that file as one transaction and rolls it back if a statement fails.
 */

import { randomUUID, webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";

const TOKEN = /^admrn_gb_[A-Za-z0-9_-]{43}$/;
const HASH = /^[a-f0-9]{64}$/;
const ID = /^credential_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function secretArgument(value) {
  return TOKEN.test(value) || HASH.test(value);
}

function parseArgs(argv) {
  if (argv.some((value) => secretArgument(value))) fail("refusing a token or hash argument");
  const [command, flag, file, extra] = argv;
  if ((command !== "issue" && command !== "revoke") || flag !== "--out" || !file || extra !== undefined) {
    fail("usage: node scripts/grok-credential.mjs <issue|revoke> --out <file>");
  }
  return { command, file };
}

function sqlString(value, pattern) {
  if (!pattern.test(value)) fail("could not build the credential file");
  return `'${value}'`;
}

const ISSUE_SQL = `-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Revoke the active Grok bearer, then insert the replacement.
-- Apply the whole file with wrangler d1 execute --remote --file.
-- D1 runs the file as one transaction. Do not commit this file.
-- The token is not in this file.

UPDATE participant_credential
SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE participant = 'grok_bot' AND kind = 'bearer' AND revoked_at IS NULL;

INSERT INTO participant_credential
  (id, participant, kind, token_sha256, owner_claimed_at, created_at)
SELECT {{id}}, 'grok_bot', 'bearer', {{hash}}, claimed_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM owner_lock
WHERE id = 1;

INSERT INTO participant_credential
  (id, participant, kind, token_sha256, owner_claimed_at, created_at)
SELECT NULL, 'grok_bot', 'bearer', NULL, NULL, NULL
WHERE changes() != 1;
`;

const REVOKE_SQL = `-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Revoke every active Grok bearer. This file has no token and no hash.
-- Apply the whole file with wrangler d1 execute --remote --file.

UPDATE participant_credential
SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE participant = 'grok_bot' AND kind = 'bearer' AND revoked_at IS NULL;
`;

async function issueSql() {
  const bytes = new Uint8Array(32);
  webcrypto.getRandomValues(bytes);
  const token = `admrn_gb_${Buffer.from(bytes).toString("base64url")}`;
  if (!TOKEN.test(token)) fail("could not build the credential file");
  const digest = await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const hash = Buffer.from(digest).toString("hex");
  const id = `credential_${randomUUID()}`;
  const sql = ISSUE_SQL.replace("{{id}}", sqlString(id, ID)).replace("{{hash}}", sqlString(hash, HASH));
  if (sql.includes(token) || sql.includes("{{")) fail("could not build the credential file");
  return { token, hash, sql };
}

function writeSql(file, sql) {
  try {
    writeFileSync(file, sql, { encoding: "utf8", mode: 0o600, flag: "wx" });
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error ? error.code : "";
    fail(code === "EEXIST" ? "output file already exists" : "could not write the SQL file");
  }
}

const { command, file } = parseArgs(process.argv.slice(2));
if (command === "revoke") {
  writeSql(file, REVOKE_SQL);
  process.stderr.write("Wrote a Grok revoke SQL file. This command does not apply it.\n");
} else {
  const { token, sql } = await issueSql();
  writeSql(file, sql);
  process.stdout.write(`${token}\n`);
  process.stderr.write("Wrote a Grok credential SQL file. The token was printed once on stdout. This command does not apply it.\n");
}
