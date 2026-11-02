-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Local authentication storage slice from docs/design/message-path.md.
-- This creates no credentials or grants. No live migration is applied here.
-- Grok bearer credentials are static; revocation and owner-lock binding govern
-- validity. OAuth/connect-code expiry remains in the future OAuth integration.

CREATE TABLE participant (
  id TEXT PRIMARY KEY CHECK (id IN ('grok_bot', 'dot')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  wake_url TEXT CHECK (wake_url IS NULL OR id = 'grok_bot')
);
INSERT INTO participant (id) VALUES ('grok_bot'), ('dot');

CREATE TABLE participant_credential (
  id TEXT NOT NULL PRIMARY KEY,
  participant TEXT NOT NULL REFERENCES participant (id),
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
CREATE UNIQUE INDEX participant_credential_one_active
  ON participant_credential (participant) WHERE revoked_at IS NULL;
