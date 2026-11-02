/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/** A temporary participant pause preserves its credential and OAuth grant. */
export const PARTICIPANT_RETRY_AFTER_SECONDS = 60;

/** Raised only after authenticating a credential against the current owner. */
export class ParticipantDisabled extends Error {
  constructor() {
    super("unavailable");
    this.name = "ParticipantDisabled";
  }
}
