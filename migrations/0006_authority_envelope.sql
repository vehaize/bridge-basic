-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Authority envelope columns and the append-only item audit.
-- Schema from docs/design/authority-envelope.md. This file adds no route,
-- binding, or Worker behavior. CI does not apply it. An operator applies it
-- to their own database after the owner approves the implementation.
--
-- apply: single-request
--
-- There is no down file. This repository does not ship down migrations.
-- Rolling back the Worker does not remove envelope_json, envelope_sha256,
-- item_audit, or item_audit_head, and it does not turn item back into a
-- rowid table. Recover with a forward fix, or with D1 Time Travel to a
-- bookmark from before this file was applied.
--
-- Item retention stays 30 days and is not in this file. Audit retention is
-- the item_audit_block_delete trigger (90 days). The two sweeps stay separate.
--
-- Existing rows keep envelope_json and envelope_sha256 null. Null is the
-- fail-closed missing envelope, not an empty allow-list. A pre-envelope row
-- has no trigger on state, so it can still be cancelled. That null on the
-- first apply is the decided choice for a pre-0006 row.
--
-- item_audit.item_id matches the runtime id: item_ plus the UUID v4 from
-- crypto.randomUUID(). D1 rejects a LIKE or GLOB pattern longer than 50
-- bytes, so the check uses length, substr, and one short glob. Every glob
-- in this file stays under that limit.
--
-- occurred_at is length 24 and IS strftime of itself. An invalid calendar
-- value makes strftime return NULL. Comparing with = is then NULL, and a
-- NULL check passes, so the bad row would be stored. IS is 0 or 1.
-- strftime keeps hour 24 as written, so the check also requires
-- substr(occurred_at, 12, 2) < '24'. A separate bound rejects a well-formed
-- timestamp before 2020-01-01T00:00:00.000Z. That value would sort before
-- the 90-day purge cutoff and be deleted immediately.
--
-- The apply must stop on the first error. D1 does this. The sqlite3 CLI
-- keeps going after an error unless it is started with -bail:
--   sqlite3 -bail database.sqlite < migrations/0006_authority_envelope.sql
-- The guard below is the first statement. It aborts when item_audit or
-- item.envelope_json already exists, before this file copies or drops a
-- row. SQLite rejects that guard text as malformed JSON. Continuing past
-- it rebuilds item and stores null envelopes. A later apply must not clear
-- an envelope that is already set.

SELECT CASE
  WHEN (
    EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'item_audit')
    OR EXISTS (SELECT 1 FROM pragma_table_info('item') WHERE name = 'envelope_json')
  ) THEN json('migration_0006_already_applied')
  ELSE 1
END;

CREATE TABLE item_authority (
  id TEXT NOT NULL PRIMARY KEY,
  sender TEXT NOT NULL CHECK (sender IN ('grok_bot', 'dot')),
  recipient TEXT NOT NULL CHECK (recipient IN ('grok_bot', 'dot')),
  kind TEXT NOT NULL CHECK (kind IN ('task', 'question', 'proposal')),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open', 'claimed', 'submitted', 'accepted', 'rejected', 'expired', 'cancelled')),
  deadline_at TEXT NOT NULL,
  result TEXT,
  sources TEXT,
  review_note TEXT,
  checked INTEGER CHECK (checked IN (0, 1)),
  idempotency_key TEXT NOT NULL,
  request_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  claimed_at TEXT,
  submitted_at TEXT,
  reviewed_at TEXT,
  cancelled_at TEXT,
  updated_at TEXT NOT NULL,
  delivered_at TEXT,
  envelope_json TEXT,
  envelope_sha256 TEXT
    CHECK (envelope_sha256 IS NULL OR (
      length(envelope_sha256) = 64 AND envelope_sha256 NOT GLOB '*[^0-9a-f]*')),
  CHECK (sender <> recipient),
  UNIQUE (sender, idempotency_key)
) WITHOUT ROWID;
INSERT INTO item_authority (
  id, sender, recipient, kind, title, body, state, deadline_at, result, sources,
  review_note, checked, idempotency_key, request_sha256, created_at, claimed_at,
  submitted_at, reviewed_at, cancelled_at, updated_at, delivered_at)
SELECT
  id, sender, recipient, kind, title, body, state, deadline_at, result, sources,
  review_note, checked, idempotency_key, request_sha256, created_at, claimed_at,
  submitted_at, reviewed_at, cancelled_at, updated_at, delivered_at
FROM item;
DROP TABLE item;
ALTER TABLE item_authority RENAME TO item;
CREATE INDEX item_recipient_created ON item (recipient, created_at, id);
CREATE INDEX item_sender_created ON item (sender, created_at, id);
CREATE INDEX item_recipient_state ON item (recipient, state, created_at, id);
CREATE INDEX item_sender_state ON item (sender, state, created_at, id);

CREATE TRIGGER item_envelope_immutable
BEFORE UPDATE OF envelope_json, envelope_sha256 ON item
BEGIN SELECT RAISE(ABORT, 'item_envelope_immutable'); END;
CREATE TRIGGER item_no_replace
BEFORE INSERT ON item
WHEN EXISTS (
    SELECT 1 FROM item AS existing
    WHERE existing.sender = NEW.sender
      AND existing.idempotency_key = NEW.idempotency_key)
  OR EXISTS (SELECT 1 FROM item AS existing WHERE existing.id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'item_envelope_immutable'); END;
CREATE TRIGGER item_no_replace_update
BEFORE UPDATE OF id, sender, idempotency_key ON item
WHEN EXISTS (
    SELECT 1 FROM item AS existing
    WHERE existing.id = NEW.id AND existing.id != OLD.id)
  OR EXISTS (
    SELECT 1 FROM item AS existing
    WHERE existing.sender = NEW.sender
      AND existing.idempotency_key = NEW.idempotency_key
      AND existing.id != OLD.id)
BEGIN SELECT RAISE(ABORT, 'item_envelope_immutable'); END;

CREATE TABLE item_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT CHECK (seq >= 1),
  event TEXT NOT NULL CHECK (event IN (
    'item_opened','item_claimed','item_submitted','item_accepted',
    'item_rejected','item_expired','item_cancelled','item_delivered',
    'envelope_rejected')),
  actor TEXT NOT NULL CHECK (actor IN ('grok_bot','dot','system')),
  item_id TEXT CHECK (item_id IS NULL OR (
    length(item_id) = 41
    AND substr(item_id, 1, 5) = 'item_'
    AND substr(item_id, 6) NOT GLOB '*[^0-9a-f-]*'
    AND substr(item_id, 14, 1) = '-'
    AND substr(item_id, 19, 1) = '-'
    AND substr(item_id, 24, 1) = '-'
    AND substr(item_id, 29, 1) = '-'
    AND substr(item_id, 20, 1) = '4'
    AND substr(item_id, 25, 1) IN ('8', '9', 'a', 'b')
    AND length(replace(substr(item_id, 6), '-', '')) = 32)),
  envelope_sha256 TEXT CHECK (envelope_sha256 IS NULL OR (
    length(envelope_sha256) = 64 AND envelope_sha256 NOT GLOB '*[^0-9a-f]*')),
  reason TEXT CHECK (reason IS NULL OR reason IN (
    'unknown_key','wrong_type','duplicate','over_limit','non_canonical_url',
    'bad_label','flag_not_false','digest_mismatch','citation_mismatch',
    'missing_envelope')),
  occurred_at TEXT NOT NULL
    CHECK (length(occurred_at) = 24
      AND occurred_at IS strftime('%Y-%m-%dT%H:%M:%fZ', occurred_at)
      AND substr(occurred_at, 12, 2) < '24'
      AND occurred_at >= '2020-01-01T00:00:00.000Z'),
  CHECK (actor != 'system' OR event = 'item_expired'),
  CHECK (event = 'envelope_rejected' OR item_id IS NOT NULL),
  CHECK ((event = 'envelope_rejected') = (reason IS NOT NULL)),
  CHECK (event != 'item_delivered' OR envelope_sha256 IS NOT NULL)
);
CREATE INDEX item_audit_expiry
  ON item_audit (item_id) WHERE event = 'item_expired';
CREATE INDEX item_audit_delivery
  ON item_audit (item_id) WHERE event = 'item_delivered';
CREATE INDEX item_audit_rejection_cap
  ON item_audit (actor, occurred_at) WHERE event = 'envelope_rejected';

CREATE TABLE item_audit_head (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  seq INTEGER NOT NULL CHECK (seq >= 0)
);
CREATE TRIGGER item_audit_head_no_replace
BEFORE INSERT ON item_audit_head
WHEN EXISTS (SELECT 1 FROM item_audit_head AS existing WHERE existing.id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_head_block_update
BEFORE UPDATE ON item_audit_head
WHEN NEW.seq <= OLD.seq
  OR NOT EXISTS (SELECT 1 FROM item_audit WHERE seq = NEW.seq)
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_head_block_delete
BEFORE DELETE ON item_audit_head
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
INSERT INTO item_audit_head (id, seq) VALUES (1, 0);

CREATE TRIGGER item_audit_no_replace
BEFORE INSERT ON item_audit
WHEN NEW.seq > 0
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_one_expiry
BEFORE INSERT ON item_audit
WHEN NEW.event = 'item_expired' AND EXISTS (
  SELECT 1 FROM item_audit
  WHERE event = 'item_expired' AND item_id = NEW.item_id)
BEGIN SELECT RAISE(ABORT, 'item_audit_one_expiry'); END;
CREATE TRIGGER item_audit_one_delivery
BEFORE INSERT ON item_audit
WHEN NEW.event = 'item_delivered' AND EXISTS (
  SELECT 1 FROM item_audit
  WHERE event = 'item_delivered' AND item_id = NEW.item_id)
BEGIN SELECT RAISE(ABORT, 'item_audit_one_delivery'); END;
CREATE TRIGGER item_audit_block_update
BEFORE UPDATE ON item_audit
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_block_delete
BEFORE DELETE ON item_audit
WHEN OLD.occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-90 days')
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_head_advance
AFTER INSERT ON item_audit
BEGIN
  SELECT RAISE(ABORT, 'item_audit_append_only')
    WHERE NEW.seq <= (SELECT seq FROM item_audit_head WHERE id = 1);
  UPDATE item_audit_head SET seq = NEW.seq WHERE id = 1 AND seq < NEW.seq;
END;
