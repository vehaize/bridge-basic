-- Copyright (C) 2026 ADMRN (admrn.com)
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Additive receipt column. Nullable, so existing rows stay valid.
-- This file is not applied by CI or by any command in this repository.
-- An operator applies it to their own database when they choose to.

ALTER TABLE item ADD COLUMN delivered_at TEXT;
