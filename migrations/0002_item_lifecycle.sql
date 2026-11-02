-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only

-- Internal lifecycle storage only. No credentials or transport are provisioned.
CREATE TABLE item (
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
  CHECK (sender <> recipient),
  UNIQUE (sender, idempotency_key)
);
CREATE INDEX item_recipient_created ON item (recipient, created_at, id);
CREATE INDEX item_sender_created ON item (sender, created_at, id);
CREATE INDEX item_recipient_state ON item (recipient, state, created_at, id);
CREATE INDEX item_sender_state ON item (sender, state, created_at, id);
