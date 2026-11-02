/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Local operator command. It writes a SQL file and, on issue, prints the new
 * Dot connect code once on stdout. It does not apply the file, call Wrangler,
 * or contact Cloudflare. The operator applies the file with:
 * wrangler d1 execute admrn-bridge --remote --file <file>
 * D1 runs that file as one transaction and rolls it back if a statement fails.
 */

import { webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";

const CODE = /^[A-Za-z0-9_-]{43}$/;
const HASH = /^[a-f0-9]{64}$/;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function secretArgument(value) {
  return CODE.test(value) || HASH.test(value);
}

function parseArgs(argv) {
  if (argv.some((value) => secretArgument(value))) fail("refusing a code or hash argument");
  const participantIndex = argv.indexOf("--participant");
  let participant = "dot";
  if (participantIndex !== -1) {
    participant = argv[participantIndex + 1];
    if (participant !== "dot" && participant !== "claude") fail("participant must be dot or claude");
    argv = [...argv.slice(0, participantIndex), ...argv.slice(participantIndex + 2)];
  }
  const [command, flag, file, extra] = argv;
  if ((command !== "issue" && command !== "expire") || flag !== "--out" || !file || extra !== undefined) {
    fail("usage: node scripts/connect-code.mjs <issue|expire> --out <file> [--participant dot|claude]");
  }
  return { command, file, participant };
}

function sqlString(value, pattern) {
  if (!pattern.test(value)) fail("could not build the connect-code file");
  return `'${value}'`;
}

// Same text as PENDING_CLAIM_SQL in src/dot-connect.ts. D1 rejects a LIKE or
// GLOB pattern longer than 50 bytes, so this check uses length and substr.
const PENDING_CLAIM_SQL = [
  "CASE WHEN json_valid(used_at) THEN",
  "  used_at = json_object(",
  "    'v', json_extract(used_at, '$.v'),",
  "    'kind', json_extract(used_at, '$.kind'),",
  "    'credential_id', json_extract(used_at, '$.credential_id'),",
  "    'until', json_extract(used_at, '$.until')",
  "  )",
  "  AND json_type(used_at, '$.v') = 'integer'",
  "  AND json_extract(used_at, '$.v') = 1",
  "  AND json_type(used_at, '$.kind') = 'text'",
  "  AND json_extract(used_at, '$.kind') = 'pending'",
  "  AND json_type(used_at, '$.credential_id') = 'text'",
  "  AND length(json_extract(used_at, '$.credential_id')) = 47",
  "  AND substr(json_extract(used_at, '$.credential_id'), 1, 11) = 'credential_'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 12) NOT GLOB '*[^0-9a-f-]*'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 20, 1) = '-'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 25, 1) = '-'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 30, 1) = '-'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 35, 1) = '-'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 26, 1) = '4'",
  "  AND substr(json_extract(used_at, '$.credential_id'), 31, 1) IN ('8', '9', 'a', 'b')",
  "  AND length(replace(substr(json_extract(used_at, '$.credential_id'), 12), '-', '')) = 32",
  "  AND json_type(used_at, '$.until') = 'integer'",
  "  ELSE 0 END",
].join("\n");

// Canonical spent record that still holds a redirect older than 120 seconds.
// D1 rejects a LIKE or GLOB pattern longer than 50 bytes. The challenge class
// is 16 bytes; the credential class is the same 12-byte pattern as above.
const SPENT_REDIRECT_SQL = [
  "json_valid(used_at)",
  "AND used_at = json_object(",
  "  'v', json_extract(used_at, '$.v'),",
  "  'kind', json_extract(used_at, '$.kind'),",
  "  'at', json_extract(used_at, '$.at'),",
  "  'credential_id', json_extract(used_at, '$.credential_id'),",
  "  'challenge', json_extract(used_at, '$.challenge'),",
  "  'location', json_extract(used_at, '$.location')",
  ")",
  "AND json_type(used_at, '$.v') = 'integer'",
  "AND json_extract(used_at, '$.v') = 1",
  "AND json_type(used_at, '$.kind') = 'text'",
  "AND json_extract(used_at, '$.kind') = 'spent'",
  "AND json_type(used_at, '$.at') = 'text'",
  "AND json_extract(used_at, '$.at') = strftime('%Y-%m-%dT%H:%M:%fZ', json_extract(used_at, '$.at'))",
  "AND json_extract(used_at, '$.at') < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-120 seconds')",
  "AND json_type(used_at, '$.credential_id') = 'text'",
  "AND length(json_extract(used_at, '$.credential_id')) = 47",
  "AND substr(json_extract(used_at, '$.credential_id'), 1, 11) = 'credential_'",
  "AND substr(json_extract(used_at, '$.credential_id'), 12) NOT GLOB '*[^0-9a-f-]*'",
  "AND substr(json_extract(used_at, '$.credential_id'), 20, 1) = '-'",
  "AND substr(json_extract(used_at, '$.credential_id'), 25, 1) = '-'",
  "AND substr(json_extract(used_at, '$.credential_id'), 30, 1) = '-'",
  "AND substr(json_extract(used_at, '$.credential_id'), 35, 1) = '-'",
  "AND substr(json_extract(used_at, '$.credential_id'), 26, 1) = '4'",
  "AND substr(json_extract(used_at, '$.credential_id'), 31, 1) IN ('8', '9', 'a', 'b')",
  "AND length(replace(substr(json_extract(used_at, '$.credential_id'), 12), '-', '')) = 32",
  "AND json_type(used_at, '$.challenge') = 'text'",
  "AND length(json_extract(used_at, '$.challenge')) = 43",
  "AND json_extract(used_at, '$.challenge') NOT GLOB '*[^A-Za-z0-9_-]*'",
  "AND json_type(used_at, '$.location') = 'text'",
  "AND length(json_extract(used_at, '$.location')) > 0",
].join("\n");

const ISSUE_SQL = `-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Insert one unused Dot connect code bound to the current owner lock.
-- The code expires 10 minutes after this file is applied. Equality is expired.
-- Apply the whole file with wrangler d1 execute --remote --file.
-- D1 runs the file as one transaction. Do not commit this file.
-- The code is not in this file.

INSERT INTO connect_code
  (code_sha256, participant, owner_claimed_at, expires_at)
SELECT {{hash}}, 'dot', claimed_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+10 minutes')
FROM owner_lock
WHERE id = 1;

INSERT INTO connect_code
  (code_sha256, participant, owner_claimed_at, expires_at)
SELECT NULL, 'dot', NULL, NULL
WHERE changes() != 1;
`;

const EXPIRE_SQL = `-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Expire every Dot connect code that is unused or held by a pending claim.
-- A pending claim is the canonical JSON token in used_at, not a spend.
-- A spent ISO-8601 timestamp is left unchanged. A canonical spent JSON record
-- is not expired. When its spend time is more than 120 seconds before
-- SQLite's clock, the redirect is removed and the rest of the record stays.
-- This file has no code and no hash.
-- Apply the whole file with wrangler d1 execute --remote --file.

UPDATE connect_code
SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 seconds')
WHERE participant = 'dot' AND (used_at IS NULL OR (
${PENDING_CLAIM_SQL}
));

UPDATE connect_code
SET used_at = json_remove(used_at, '$.location')
WHERE participant = 'dot' AND (
${SPENT_REDIRECT_SQL}
);
`;

async function issueSql(participant) {
  const bytes = new Uint8Array(32);
  webcrypto.getRandomValues(bytes);
  const code = Buffer.from(bytes).toString("base64url");
  if (!CODE.test(code)) fail("could not build the connect-code file");
  const digest = await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(code));
  const hash = Buffer.from(digest).toString("hex");
  const sql = participantSql(ISSUE_SQL, participant).replace("{{hash}}", sqlString(hash, HASH));
  if (sql.includes(code) || sql.includes("{{")) fail("could not build the connect-code file");
  return { code, hash, sql };
}

function writeSql(file, sql) {
  try {
    writeFileSync(file, sql, { encoding: "utf8", mode: 0o600, flag: "wx" });
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error ? error.code : "";
    fail(code === "EEXIST" ? "output file already exists" : "could not write the SQL file");
  }
}

// Only these two literals can enter generated SQL; parseArgs rejects everything else.
function participantSql(sql, participant) {
  return participant === "claude" ? sql.replaceAll("'dot'", "'claude'").replaceAll("Dot", "Claude") : sql;
}

const { command, file, participant } = parseArgs(process.argv.slice(2));
if (command === "expire") {
  writeSql(file, participantSql(EXPIRE_SQL, participant));
  process.stderr.write(`Wrote a ${participant === "dot" ? "Dot" : "Claude"} connect-code expire SQL file. This command does not apply it.\n`);
} else {
  const { code, sql } = await issueSql(participant);
  writeSql(file, sql);
  process.stdout.write(`${code}\n`);
  process.stderr.write(`Wrote a ${participant === "dot" ? "Dot" : "Claude"} connect-code SQL file. The code was printed once on stdout. It expires 10 minutes after the file is applied. This command does not apply it.\n`);
}
