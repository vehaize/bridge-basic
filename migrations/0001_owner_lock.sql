-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Owner lock. See docs/design/owner-lock.md, Storage.

CREATE TABLE owner_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  owner_email TEXT NOT NULL CHECK (length(trim(owner_email)) > 0),
  claimed_at TEXT NOT NULL,
  claim_source TEXT NOT NULL CHECK (claim_source = 'first-boot')
);

CREATE TABLE bootstrap_secret_spend (
  secret_sha256 TEXT NOT NULL PRIMARY KEY CHECK (length(secret_sha256) > 0),
  spent_at TEXT NOT NULL
);
