-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- One-time Dot connect codes. See docs/design/message-path.md, Storage.
-- This file is not applied by CI. An operator applies it on their own account
-- after review. Do not put a code, a hash of a real code, or an email here.

CREATE TABLE connect_code (
  code_sha256 TEXT NOT NULL PRIMARY KEY,
  participant TEXT NOT NULL CHECK (participant = 'dot'),
  owner_claimed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
