# Migration 0007: seeded disposable-D1 rehearsal

**Remote status: NOT YET RUN.** This page prepares a future owner-authorized
rehearsal. The accompanying test uses synthetic, in-memory SQLite only; it does
not establish D1 execution, rollback, or teardown success. No Worker, client,
credential, or test instance is created by this work. License: AGPL-3.0-only.

Use the [installation](install.md) and [upgrade and recovery](upgrade-and-recovery.md) guides for operator procedures.
It specifically tests upgrading a **populated 0001-0006 database** through
`0007_claude_basic_participant.sql`. Applying all seven files to an empty database
does not exercise this case. Record the full reviewed checkout SHA
and migration-file hashes used for any later rehearsal; stop if they differ from
the approved plan. Never edit the released files or execute 0007 statement by
statement.

## Owner gates and isolation

Every gate below is **NOT YET RUN / awaiting owner authorization**. A runbook is
not permission to operate Cloudflare. Stop on a failed check, unknown target,
missing approval, or uncertain command result. Read the target and current state
before retrying; do not rerun a seed or migration to diagnose an ambiguous apply.

| Gate | Required owner decision and operator evidence |
| --- | --- |
| Step 0: target/create | Name one disposable account and a new D1 database `admrn-bridge-0007-rehearsal-<RUN_SUFFIX>`; approve creation and cost. It must not be `admrn-bridge`, `admrn-bridge-test`, or a database bound to any Worker. A name collision stops the run. |
| Step 1: 0001-0006/seed | Approve these six migrations and the synthetic SQL below on that database only. Confirm no clients, cron, replication consumer, or other writer can touch it. |
| Step 2: 0007 | Review all preflight results, the private export/bookmark, exact database ID, and unchanged migration bytes; approve the single migration request. |
| Step 3: append probe | Approve one synthetic audit insert after preservation checks pass. This is a write, distinct from the read-only checks. |
| Step 4: teardown | Confirm the exact disposable name and ID again; approve deleting that database and only this run's private local directory. |

Keep account/database IDs, bookmarks, command receipts, exports, and the private
config outside git. Never substitute production data. The invented hashes below
are repeated letters, not hashes of real tokens; the invented email is `.invalid`.
The envelope marker is deliberately synthetic and is not a usable authority
envelope. Do not bind this seeded database to a Worker.

## Stage and apply only 0001-0006 — NOT YET RUN

Use the repository's lockfile-installed Wrangler (record `npx --no-install
wrangler --version`) and an interactive terminal. From the pinned checkout, make
a new private staging directory outside the clone. In the following POSIX-shell
examples, `REHEARSAL_DIR` is its reviewed absolute path, `REHEARSAL_CONFIG` is
`$REHEARSAL_DIR/wrangler.jsonc`, and `DB_NAME` is the exact owner-approved name.
Do not reuse another run's directory, IDs, config, or database.

Start that shell with `set -eu` and `umask 077`. Do not paste multiple phases at
once: the list/read-back in each phase must be inspected before the next write.

Create the private config with the disposable `account_id`, that `name`, and no
Worker entrypoint, routes, KV, or secrets. After the owner authorizes creation:

```sh
npx --no-install wrangler d1 create "$DB_NAME" --config "$REHEARSAL_CONFIG"
```

Add the newly returned ID to its sole D1 binding:

```jsonc
"d1_databases": [{
  "binding": "DB",
  "database_name": "admrn-bridge-0007-rehearsal-<RUN_SUFFIX>",
  "database_id": "<NEW_DISPOSABLE_DATABASE_ID>",
  "migrations_dir": "./migrations",
  "migrations_table": "d1_migrations"
}]
```

The migration directory is relative to the private config. Copy the six files
without changing the tracked `migrations/` directory:

```sh
mkdir "$REHEARSAL_DIR/migrations"
for name in 0001_owner_lock.sql 0002_item_lifecycle.sql \
  0003_participant_credentials.sql 0004_connect_code.sql \
  0005_item_receipt.sql 0006_authority_envelope.sql; do
  cp "migrations/$name" "$REHEARSAL_DIR/migrations/$name" || exit 1
  cmp "migrations/$name" "$REHEARSAL_DIR/migrations/$name" || exit 1
done
npx --no-install wrangler d1 migrations list DB --remote --config "$REHEARSAL_CONFIG"
```

Pass: precisely 0001-0006 are pending, staged bytes match, and the printed target
is the approved new database. No 0007 file is staged yet. After gate C04-1:

```sh
npx --no-install wrangler d1 migrations apply DB --remote --config "$REHEARSAL_CONFIG"
npx --no-install wrangler d1 migrations list DB --remote --config "$REHEARSAL_CONFIG"
```

Pass: apply succeeds and the list says `No migrations to apply!` **for the staged
six files**. This alone says nothing about 0007. Do not insert tracking rows by
hand or use `d1 execute --file` to apply a schema migration. Wrangler manages
[`d1_migrations` and the migration directory](https://developers.cloudflare.com/d1/reference/migrations/).

## Seed and capture the baseline — NOT YET RUN

Copy the following complete block to `$REHEARSAL_DIR/seed.sql`. Run once with
`npx --no-install wrangler d1 execute DB --remote --config "$REHEARSAL_CONFIG"
--file "$REHEARSAL_DIR/seed.sql"`. This is synthetic fixture SQL, not a migration.
An error stops the run; never continue from a partly seeded or uncertain state.

```sql
-- rehearsal: seed
INSERT INTO owner_lock VALUES
  (1, 'synthetic-owner@example.invalid', '2026-10-27T00:00:00.000Z', 'first-boot');
INSERT INTO bootstrap_secret_spend VALUES
  ('synthetic-bootstrap-hash', '2026-10-27T00:00:00.000Z');
UPDATE participant SET enabled = 0 WHERE id = 'dot';
UPDATE participant SET wake_url = 'https://receiver.example.invalid/hook' WHERE id = 'grok_bot';
INSERT INTO participant_credential VALUES
  ('synthetic-grok', 'grok_bot', 'bearer',
   'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', NULL,
   '2026-10-27T00:00:00.000Z', '2026-10-27T00:00:00.000Z', NULL),
  ('synthetic-dot', 'dot', 'oauth_grant', NULL,
   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
   '2026-10-27T00:00:00.000Z', '2026-10-27T00:00:00.000Z', NULL);
INSERT INTO connect_code VALUES
  ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'dot',
   '2026-10-27T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 'synthetic-spent');
INSERT INTO item
  (id, sender, recipient, kind, title, body, state, deadline_at, result, sources,
   review_note, checked, idempotency_key, request_sha256, created_at, claimed_at,
   submitted_at, reviewed_at, cancelled_at, updated_at, delivered_at,
   envelope_json, envelope_sha256)
VALUES
  ('item_01234567-89ab-4cde-8fab-0123456789ab', 'dot', 'grok_bot', 'task',
   'Synthetic accepted', 'Local fixture only', 'accepted', '2099-01-01T00:00:00.000Z',
   'Synthetic result', '[]', 'Synthetic review', 1, 'req_rehearsal_001',
   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
   '2026-10-27T00:00:00.000Z', '2026-10-27T00:00:00.000Z',
   '2026-10-27T00:00:00.000Z', '2026-10-27T00:00:00.000Z', NULL,
   '2026-10-27T00:00:00.000Z', '2026-10-27T00:00:00.000Z',
   '{"synthetic": "unchanged bytes"}',
   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
  ('item_11234567-89ab-4cde-8fab-0123456789ab', 'grok_bot', 'dot', 'question',
   'Synthetic cancelled', 'Null envelope is preserved', 'cancelled', '2026-10-27T00:00:00.000Z',
   NULL, NULL, NULL, NULL, 'req_rehearsal_002',
   'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
   '2026-10-27T00:00:00.000Z', NULL, NULL, NULL, '2026-10-27T00:00:00.000Z',
   '2026-10-27T00:00:00.000Z', NULL, NULL, NULL),
  ('item_21234567-89ab-4cde-8fab-0123456789ab', 'dot', 'grok_bot', 'proposal',
   'Synthetic open', 'Local fixture only', 'open', '2099-01-01T00:00:00.000Z',
   NULL, NULL, NULL, NULL, 'req_rehearsal_003',
   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
   '2026-10-27T00:00:00.000Z', NULL, NULL, NULL, NULL,
   '2026-10-27T00:00:00.000Z', NULL, NULL, NULL);
INSERT INTO item_audit (event, actor, item_id, envelope_sha256, occurred_at) VALUES
  ('item_opened', 'dot', 'item_01234567-89ab-4cde-8fab-0123456789ab', NULL, '2020-01-01T00:00:00.000Z'),
  ('item_claimed', 'grok_bot', 'item_01234567-89ab-4cde-8fab-0123456789ab', NULL, '2020-01-01T00:00:00.000Z'),
  ('item_delivered', 'grok_bot', 'item_01234567-89ab-4cde-8fab-0123456789ab',
   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '2020-01-01T00:00:00.000Z'),
  ('item_expired', 'system', 'item_11234567-89ab-4cde-8fab-0123456789ab', NULL, '2020-01-01T00:00:00.000Z'),
  ('item_opened', 'dot', 'item_21234567-89ab-4cde-8fab-0123456789ab', NULL, '2020-01-01T00:00:00.000Z');
-- These old rows are beyond audit retention. Preserve a gap AND a removed tail.
DELETE FROM item_audit WHERE seq IN (2, 5);
```

Each SQL block below is read-only. Copy a block into a private `.sql` file and
use `d1 execute DB --remote --config "$REHEARSAL_CONFIG" --file <absolute-file>`
with the installed Wrangler. Run **all common checks** before and after 0007,
and the matching phase check. Pass requires every `result` to be `PASS`, the
documented inspection results, and no SQL errors. An empty/missing result is a
failure. Store only sanitized pass/fail summaries in shared evidence.

### Common row counts and audit sequence

```sql
-- rehearsal: counts
SELECT 'owner_lock' AS check_name, actual, 1 AS expected,
  CASE WHEN actual = 1 THEN 'PASS' ELSE 'FAIL' END AS result
FROM (SELECT count(*) AS actual FROM owner_lock);
SELECT 'bootstrap_secret_spend' AS check_name, actual, 1 AS expected,
  CASE WHEN actual = 1 THEN 'PASS' ELSE 'FAIL' END AS result
FROM (SELECT count(*) AS actual FROM bootstrap_secret_spend);
SELECT 'participant_credential' AS check_name, actual, 2 AS expected,
  CASE WHEN actual = 2 THEN 'PASS' ELSE 'FAIL' END AS result
FROM (SELECT count(*) AS actual FROM participant_credential);
SELECT 'connect_code' AS check_name, actual, 1 AS expected,
  CASE WHEN actual = 1 THEN 'PASS' ELSE 'FAIL' END AS result
FROM (SELECT count(*) AS actual FROM connect_code);
SELECT 'item' AS check_name, actual, 3 AS expected,
  CASE WHEN actual = 3 THEN 'PASS' ELSE 'FAIL' END AS result
FROM (SELECT count(*) AS actual FROM item);
SELECT 'item_audit' AS check_name, actual, 3 AS expected,
  CASE WHEN actual = 3 THEN 'PASS' ELSE 'FAIL' END AS result
FROM (SELECT count(*) AS actual FROM item_audit);
SELECT 'item_audit_head' AS check_name, actual, 1 AS expected,
  CASE WHEN actual = 1 THEN 'PASS' ELSE 'FAIL' END AS result
FROM (SELECT count(*) AS actual FROM item_audit_head);
```

Keep these as seven separate statements. Each returns its table's count,
expected count, and `PASS`/`FAIL` without a compound `UNION ALL` query, which
exceeded the remote D1 compound-SELECT limit in the previous counts block.

```sql
-- rehearsal: audit
SELECT 'audit_gap_and_high_water' AS check_name,
  CASE WHEN (SELECT group_concat(seq, ',') FROM (SELECT seq FROM item_audit ORDER BY seq)) = '1,3,4'
    AND (SELECT count(*) FROM item_audit_head) = 1
    AND (SELECT seq FROM item_audit_head WHERE id = 1) = 5
    AND (SELECT count(*) FROM sqlite_sequence WHERE name = 'item_audit') = 1
    AND (SELECT seq FROM sqlite_sequence WHERE name = 'item_audit') = 5
    THEN 'PASS' ELSE 'FAIL' END AS result;
```

Pass: audit rows stay `1,3,4`, maximum retained sequence is 4, while both head
and AUTOINCREMENT stay 5. Comparing the head only to `MAX(seq)` would miss the
deleted-tail case. The post-migration append below must allocate 6, never 5.

### Common guards, indexes, and temporary-table absence

```sql
-- rehearsal: objects
WITH expected(type, name, tbl_name) AS (VALUES
  ('index', 'participant_credential_one_active', 'participant_credential'),
  ('index', 'item_recipient_created', 'item'),
  ('index', 'item_sender_created', 'item'),
  ('index', 'item_recipient_state', 'item'),
  ('index', 'item_sender_state', 'item'),
  ('index', 'item_audit_expiry', 'item_audit'),
  ('index', 'item_audit_delivery', 'item_audit'),
  ('index', 'item_audit_rejection_cap', 'item_audit'),
  ('trigger', 'item_envelope_immutable', 'item'),
  ('trigger', 'item_no_replace', 'item'),
  ('trigger', 'item_no_replace_update', 'item'),
  ('trigger', 'item_audit_no_replace', 'item_audit'),
  ('trigger', 'item_audit_one_expiry', 'item_audit'),
  ('trigger', 'item_audit_one_delivery', 'item_audit'),
  ('trigger', 'item_audit_block_update', 'item_audit'),
  ('trigger', 'item_audit_block_delete', 'item_audit'),
  ('trigger', 'item_audit_head_advance', 'item_audit'),
  ('trigger', 'item_audit_head_no_replace', 'item_audit_head'),
  ('trigger', 'item_audit_head_block_update', 'item_audit_head'),
  ('trigger', 'item_audit_head_block_delete', 'item_audit_head')
), actual AS (
  SELECT type, name, tbl_name FROM sqlite_schema
  WHERE type IN ('index', 'trigger') AND name NOT GLOB 'sqlite_*'
)
SELECT 'named_indexes_and_triggers' AS check_name,
  CASE WHEN NOT EXISTS (SELECT * FROM expected EXCEPT SELECT * FROM actual)
    AND NOT EXISTS (SELECT * FROM actual EXCEPT SELECT * FROM expected)
    THEN 'PASS' ELSE 'FAIL' END AS result;
```

```sql
-- rehearsal: residue
SELECT 'no_basic_residue' AS check_name,
  CASE WHEN NOT EXISTS (SELECT 1 FROM sqlite_schema
      WHERE name GLOB '*_basic' OR tbl_name GLOB '*_basic')
    AND NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name GLOB '*_basic')
    THEN 'PASS' ELSE 'FAIL' END AS result;
```

Names alone are insufficient. Also run these inspections at both stages:

```sql
-- rehearsal: inspect
SELECT type, name, tbl_name, sql FROM sqlite_schema
  WHERE type IN ('index', 'trigger') AND name NOT GLOB 'sqlite_*'
  ORDER BY type, name;
PRAGMA index_list('item');
PRAGMA index_list('participant_credential');
PRAGMA index_list('participant');
PRAGMA index_list('connect_code');
PRAGMA foreign_keys;
PRAGMA foreign_key_check;
PRAGMA foreign_key_list('participant_credential');
PRAGMA quick_check;
SELECT sql FROM sqlite_schema WHERE name = 'item';
SELECT name, seq FROM sqlite_sequence ORDER BY name;
```

Pass: eight named indexes and twelve triggers have the same definitions before
and after (ignore whitespace and table-name quoting only). The partial unique
credential index still uses `WHERE revoked_at IS NULL`; the audit indexes still
filter expiry, delivery, and rejection events; item indexes retain their ordered
columns. Inspect each returned index with `PRAGMA index_info('<returned-name>');`
compare uniqueness, partial flag, and ordered key columns, including automatic
primary/unique indexes. Automatic index names may change when tables are renamed.
`item` remains `WITHOUT ROWID`. Foreign keys report enabled (`1`),
`foreign_key_check` returns **zero rows**, and the credential FK returns exactly
one row: `participant -> participant.id`, `NO ACTION` on update/delete, match
`NONE`. `quick_check` returns one `ok`. `sqlite_sequence` contains exactly the
audit row (5) and migration-tracker row (6 before / 7 after); no `_basic` names.
Any other result fails. These are [D1 schema inspections](https://developers.cloudflare.com/d1/sql-api/sql-statements/),
not permission to switch off constraints.

Save and compare the complete synthetic row results, not just counts:

```sql
-- rehearsal: snapshots
SELECT * FROM owner_lock ORDER BY id;
SELECT * FROM bootstrap_secret_spend ORDER BY secret_sha256;
SELECT * FROM participant_credential ORDER BY id;
SELECT * FROM connect_code ORDER BY code_sha256;
SELECT * FROM item ORDER BY id;
SELECT * FROM item_audit ORDER BY seq;
SELECT * FROM item_audit_head ORDER BY id;
SELECT * FROM participant ORDER BY id;
SELECT id, name, applied_at FROM d1_migrations ORDER BY id;
```

Pass: every pre-existing value, null, timestamp, spend marker, envelope byte,
credential and sequence survives exactly. Only the new `claude` participant and
the 0007 tracking row are added. Retain the first six tracker rows unchanged.
These queries are safe here because this database contains only the provided
synthetic fixtures; **never run/share these snapshots on a real-client database**.

### Pre-0007 roster and tracking

```sql
-- rehearsal: before
WITH expected(name) AS (VALUES
  ('0001_owner_lock.sql'), ('0002_item_lifecycle.sql'),
  ('0003_participant_credentials.sql'), ('0004_connect_code.sql'),
  ('0005_item_receipt.sql'), ('0006_authority_envelope.sql'))
SELECT 'tracking_0001_0006' AS check_name,
  CASE WHEN (SELECT count(*) FROM d1_migrations) = 6
    AND NOT EXISTS (SELECT name FROM expected EXCEPT SELECT name FROM d1_migrations)
    AND (SELECT seq FROM sqlite_sequence WHERE name = 'd1_migrations') = 6
    THEN 'PASS' ELSE 'FAIL' END AS result
UNION ALL
SELECT 'roster_before', CASE WHEN (SELECT count(*) FROM participant) = 2
  AND EXISTS (SELECT 1 FROM participant WHERE id = 'dot' AND enabled = 0 AND wake_url IS NULL)
  AND EXISTS (SELECT 1 FROM participant WHERE id = 'grok_bot' AND enabled = 1
    AND wake_url = 'https://receiver.example.invalid/hook')
  THEN 'PASS' ELSE 'FAIL' END;
```

Pass all common checks, inspect/snapshot comparisons to the seed, and this
preflight before capturing the backup:

```sh
npx --no-install wrangler d1 export DB --remote --config "$REHEARSAL_CONFIG" --output "$REHEARSAL_DIR/before-0007.sql"
npx --no-install wrangler d1 time-travel info DB --config "$REHEARSAL_CONFIG"
```

Record the bookmark privately. Do not attempt a restore as part of C-04; use the
separately authorized [recovery procedure](upgrade-and-recovery.md) if needed.

## Apply 0007 and verify — NOT YET RUN

After gate C04-2, stage the unchanged seventh file. The list must show **only**
0007 pending; a different list stops the run before apply.

```sh
cp migrations/0007_claude_basic_participant.sql "$REHEARSAL_DIR/migrations/0007_claude_basic_participant.sql"
cmp migrations/0007_claude_basic_participant.sql "$REHEARSAL_DIR/migrations/0007_claude_basic_participant.sql"
npx --no-install wrangler d1 migrations list DB --remote --config "$REHEARSAL_CONFIG"
```

Only after verifying that list and the exact disposable target, apply:

```sh
npx --no-install wrangler d1 migrations apply DB --remote --config "$REHEARSAL_CONFIG"
npx --no-install wrangler d1 migrations list DB --remote --config "$REHEARSAL_CONFIG"
```

Pass: the apply completes and the final list has no pending migrations. Run all
common checks and compare the snapshots before proceeding. A command failure or
timeout is not proof of rollback; inspect tracking and schema first. Wrangler's
[migration failure behavior](https://developers.cloudflare.com/d1/wrangler-commands/#d1-migrations-apply)
does not replace observable postconditions.

```sql
-- rehearsal: after
WITH expected(name) AS (VALUES
  ('0001_owner_lock.sql'), ('0002_item_lifecycle.sql'),
  ('0003_participant_credentials.sql'), ('0004_connect_code.sql'),
  ('0005_item_receipt.sql'), ('0006_authority_envelope.sql'),
  ('0007_claude_basic_participant.sql'))
SELECT 'tracking_0001_0007' AS check_name,
  CASE WHEN (SELECT count(*) FROM d1_migrations) = 7
    AND NOT EXISTS (SELECT name FROM expected EXCEPT SELECT name FROM d1_migrations)
    AND (SELECT name FROM d1_migrations WHERE id = 7) = '0007_claude_basic_participant.sql'
    AND (SELECT seq FROM sqlite_sequence WHERE name = 'd1_migrations') = 7
    THEN 'PASS' ELSE 'FAIL' END AS result
UNION ALL
SELECT 'roster_after', CASE WHEN (SELECT count(*) FROM participant) = 3
  AND EXISTS (SELECT 1 FROM participant WHERE id = 'dot' AND enabled = 0 AND wake_url IS NULL)
  AND EXISTS (SELECT 1 FROM participant WHERE id = 'grok_bot' AND enabled = 1
    AND wake_url = 'https://receiver.example.invalid/hook')
  AND EXISTS (SELECT 1 FROM participant WHERE id = 'claude' AND enabled = 1 AND wake_url IS NULL)
  AND NOT EXISTS (SELECT 1 FROM participant_credential WHERE participant = 'claude')
  AND NOT EXISTS (SELECT 1 FROM connect_code WHERE participant = 'claude')
  THEN 'PASS' ELSE 'FAIL' END;
```

After C04-3, perform this **write probe** once. It is not part of the read-only
checks. Do not run the common pre-append audit/count expectations after it.

```sql
-- rehearsal: append
INSERT INTO item_audit (event, actor, item_id, occurred_at) VALUES
  ('item_opened', 'claude', 'item_21234567-89ab-4cde-8fab-0123456789ab', '2026-10-27T00:00:00.000Z');
```

Then run the read-only check:

```sql
-- rehearsal: appended
SELECT 'next_audit_sequence' AS check_name,
  CASE WHEN (SELECT group_concat(seq, ',') FROM (SELECT seq FROM item_audit ORDER BY seq)) = '1,3,4,6'
    AND (SELECT seq FROM item_audit_head WHERE id = 1) = 6
    AND (SELECT seq FROM sqlite_sequence WHERE name = 'item_audit') = 6
    AND EXISTS (SELECT 1 FROM item_audit WHERE seq = 6 AND actor = 'claude'
      AND event = 'item_opened' AND item_id = 'item_21234567-89ab-4cde-8fab-0123456789ab')
    THEN 'PASS' ELSE 'FAIL' END AS result;
```

Pass: four audit rows and sequence/head 6. Re-run `foreign_key_check` and
`quick_check`; require zero violations and `ok`. The local regression also tests
guard refusals and the case where retention deleted **every** audit row. It
simulates the Wrangler ledger locally; it does not run the remote runner.

## Teardown and sanitized evidence — NOT YET RUN

At C04-4 the owner compares the exact name and ID with the creation receipt and
confirms no Worker references it. Only then, in an interactive terminal:

```sh
npx --no-install wrangler d1 delete "$DB_NAME" --config "$REHEARSAL_CONFIG"
npx --no-install wrangler d1 list --config "$REHEARSAL_CONFIG"
```

Do not skip confirmation. Pass only after the delete succeeds **and** the
database is absent from the complete listing (check every page if paginated).
An uncertain delete stays `UNKNOWN`, not `PASS`; inspect before any retry.
After storing sanitized evidence, remove only this run's reviewed absolute
private directory, including config, export, SQL copies, and raw output. No
recursive deletion command is supplied for a user-selected path. No Worker/KV
resource was needed or should be deleted. A remaining resource or file is a
failed teardown that must name its owner and next action.

Copy this template outside the clone; retain `NOT_YET_RUN` until observed:

```yaml
objective: C-04
runtime_status: NOT_YET_RUN
reviewed_checkout_sha: UNRECORDED
migration_hashes_verified: NOT_YET_RUN
wrangler_version: UNRECORDED
owner_gate_refs: {Step 0: PENDING, Step 1: PENDING, Step 2: PENDING, Step 3: PENDING, Step 4: PENDING}
target_disposable_and_unbound: NOT_YET_RUN
prior_migrations_and_tracking: NOT_YET_RUN
seed_and_preflight: NOT_YET_RUN
private_backup_and_bookmark_recorded: NOT_YET_RUN
only_0007_pending_then_none: NOT_YET_RUN
row_bytes_counts_and_roster: NOT_YET_RUN
audit_gap_head_and_sqlite_sequence: NOT_YET_RUN
trigger_index_definitions_and_foreign_keys: NOT_YET_RUN
basic_residue_absent: NOT_YET_RUN
tracking_rows_preserved: NOT_YET_RUN
next_sequence_6: NOT_YET_RUN
remote_deletion_verified: NOT_YET_RUN
local_private_files_removed: NOT_YET_RUN
failure_or_unknown_gate: NONE_OBSERVED_NOT_RUN
follow_up_owner_and_action: UNASSIGNED
```

Shared evidence contains no account/database ID, bookmark, export, credential,
real hash, email, token, or raw provider/Cloudflare log. Local synthetic test
results must be labeled separately from this remote runtime record.
