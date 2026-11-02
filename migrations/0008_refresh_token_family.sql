-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Hash-only refresh history. Idempotent for the existing migration runner.
-- Apply only through an independently authorized rollout (or synthetic tests).

CREATE TABLE IF NOT EXISTS oauth_refresh_family (
  id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL REFERENCES participant_credential (id),
  participant TEXT NOT NULL REFERENCES participant (id),
  client_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  current_sha256 TEXT,
  previous_sha256 TEXT,
  previous_until_ms INTEGER,
  previous_used INTEGER NOT NULL DEFAULT 0 CHECK (previous_used IN (0, 1)),
  position INTEGER NOT NULL DEFAULT 0 CHECK (position >= 0),
  pending_id TEXT,
  revoked_at TEXT,
  UNIQUE (participant, grant_id)
);
CREATE TABLE IF NOT EXISTS oauth_refresh_token (
  token_sha256 TEXT PRIMARY KEY CHECK (length(token_sha256) = 64),
  family_id TEXT NOT NULL REFERENCES oauth_refresh_family (id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK (position >= 0),
  UNIQUE (family_id, position)
);
CREATE INDEX IF NOT EXISTS oauth_refresh_family_credential
  ON oauth_refresh_family (credential_id);

-- A revoked family cannot be made live by clearing its timestamp.
CREATE TRIGGER IF NOT EXISTS oauth_family_no_unrevoke
BEFORE UPDATE OF revoked_at ON oauth_refresh_family
WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL
BEGIN
  SELECT RAISE(ABORT, 'revocation_immutable');
END;

-- Revocation is an in-place timestamp, synchronized in the same transaction.
CREATE TRIGGER IF NOT EXISTS oauth_family_revoke_credential
AFTER UPDATE OF revoked_at ON oauth_refresh_family
WHEN NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL
BEGIN
  UPDATE participant_credential SET revoked_at = NEW.revoked_at
    WHERE id = NEW.credential_id AND revoked_at IS NULL;
END;
CREATE TRIGGER IF NOT EXISTS oauth_credential_revoke_family
AFTER UPDATE OF revoked_at ON participant_credential
WHEN NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL
BEGIN
  UPDATE oauth_refresh_family SET revoked_at = NEW.revoked_at
    WHERE credential_id = NEW.id AND revoked_at IS NULL;
END;
