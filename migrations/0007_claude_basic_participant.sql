-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Claude joins Basic. Preserve existing rows and all authority/audit guards.
-- Run as one request, stopping at the first error. No transaction wrapper and
-- no down migration. See docs/design/claude-basic-participant.md.
-- This task does not apply this file to any operator database.
-- apply: single-request

SELECT CASE WHEN EXISTS (SELECT 1 FROM participant WHERE id = 'claude')
  THEN json('migration_0007_already_applied') ELSE 1 END;

CREATE TABLE participant_basic (
  id TEXT PRIMARY KEY CHECK (id IN ('grok_bot', 'dot', 'claude')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  wake_url TEXT CHECK (wake_url IS NULL OR id = 'grok_bot')
);
INSERT INTO participant_basic SELECT * FROM participant;
INSERT INTO participant_basic (id) VALUES ('claude');

CREATE TABLE participant_credential_basic (
  id TEXT NOT NULL PRIMARY KEY,
  participant TEXT NOT NULL REFERENCES participant_basic (id),
  kind TEXT NOT NULL CHECK (kind IN ('bearer', 'oauth_grant')),
  token_sha256 TEXT UNIQUE,
  connect_code_sha256 TEXT UNIQUE,
  owner_claimed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  CHECK ((kind = 'bearer') = (participant = 'grok_bot')),
  CHECK ((kind = 'bearer') = (token_sha256 IS NOT NULL)),
  CHECK ((kind = 'oauth_grant') = (connect_code_sha256 IS NOT NULL))
);
INSERT INTO participant_credential_basic SELECT * FROM participant_credential;
-- Copy the referencing table first; foreign_keys can remain enabled throughout.
DROP TABLE participant_credential;
DROP TABLE participant;
ALTER TABLE participant_basic RENAME TO participant;
ALTER TABLE participant_credential_basic RENAME TO participant_credential;
CREATE UNIQUE INDEX participant_credential_one_active
  ON participant_credential (participant) WHERE revoked_at IS NULL;

CREATE TABLE connect_code_basic (
  code_sha256 TEXT NOT NULL PRIMARY KEY,
  participant TEXT NOT NULL CHECK (participant IN ('dot', 'claude')),
  owner_claimed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
INSERT INTO connect_code_basic SELECT * FROM connect_code;
DROP TABLE connect_code;
ALTER TABLE connect_code_basic RENAME TO connect_code;

CREATE TABLE item_basic (
  id TEXT NOT NULL PRIMARY KEY,
  sender TEXT NOT NULL CHECK (sender IN ('grok_bot', 'dot', 'claude')),
  recipient TEXT NOT NULL CHECK (recipient IN ('grok_bot', 'dot', 'claude')),
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
INSERT INTO item_basic (
  id, sender, recipient, kind, title, body, state, deadline_at, result, sources,
  review_note, checked, idempotency_key, request_sha256, created_at, claimed_at,
  submitted_at, reviewed_at, cancelled_at, updated_at, delivered_at, envelope_json, envelope_sha256)
SELECT
  id, sender, recipient, kind, title, body, state, deadline_at, result, sources,
  review_note, checked, idempotency_key, request_sha256, created_at, claimed_at,
  submitted_at, reviewed_at, cancelled_at, updated_at, delivered_at, envelope_json, envelope_sha256
FROM item;
DROP TABLE item;
ALTER TABLE item_basic RENAME TO item;
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

CREATE TABLE item_audit_basic (
  seq INTEGER PRIMARY KEY AUTOINCREMENT CHECK (seq >= 1),
  event TEXT NOT NULL CHECK (event IN (
    'item_opened','item_claimed','item_submitted','item_accepted',
    'item_rejected','item_expired','item_cancelled','item_delivered',
    'envelope_rejected')),
  actor TEXT NOT NULL CHECK (actor IN ('grok_bot','dot','claude','system')),
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
INSERT INTO item_audit_basic SELECT * FROM item_audit;
-- Retention can remove the highest row. Never reuse its sequence number.
INSERT INTO sqlite_sequence (name, seq)
  SELECT 'item_audit_basic', 0
  WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'item_audit_basic');
UPDATE sqlite_sequence
  SET seq = max(seq,
    coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'item_audit'), 0),
    (SELECT seq FROM item_audit_head WHERE id = 1))
  WHERE name = 'item_audit_basic';
-- Temporarily remove only the head trigger that references the rebuilt table.
-- The head row and its other protections stay in place.
DROP TRIGGER item_audit_head_block_update;
DROP TABLE item_audit;
ALTER TABLE item_audit_basic RENAME TO item_audit;

CREATE INDEX item_audit_expiry
  ON item_audit (item_id) WHERE event = 'item_expired';
CREATE INDEX item_audit_delivery
  ON item_audit (item_id) WHERE event = 'item_delivered';
CREATE INDEX item_audit_rejection_cap
  ON item_audit (actor, occurred_at) WHERE event = 'envelope_rejected';

CREATE TRIGGER item_audit_head_block_update
BEFORE UPDATE ON item_audit_head
WHEN NEW.seq <= OLD.seq
  OR NOT EXISTS (SELECT 1 FROM item_audit WHERE seq = NEW.seq)
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
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
