-- Synthetic test storage only; canonical sketch: docs/design/message-path.md.
-- No production migration or operator provisioning is part of this slice.
CREATE TABLE IF NOT EXISTS connect_code (
  code_sha256 TEXT NOT NULL PRIMARY KEY,
  participant TEXT NOT NULL CHECK (participant = 'dot'),
  owner_claimed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
