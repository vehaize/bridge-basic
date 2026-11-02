/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// A D1 stand-in backed by node:sqlite and the real migrations. It supports the
// session API the Worker uses and records every statement the Worker prepares.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { fileURLToPath } from "node:url";

const MIGRATIONS_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../migrations",
);

interface Statement {
  sql: string;
  values: SQLInputValue[];
}

const REFERENCE_CLOCK = new DatabaseSync(":memory:");

/**
 * Pin SQLite's 'now' to `now()`. Every other strftime argument keeps SQLite's
 * own result, so the item_audit CHECK that compares occurred_at with
 * strftime(occurred_at) still sees the stored value, not the pinned clock.
 */
export function pinSqliteNow(sqlite: DatabaseSync, now: () => number): void {
  sqlite.function("strftime", { varargs: true }, (...args: SQLInputValue[]) => {
    const values = args.map((value) => (value === "now" ? new Date(now()).toISOString() : value));
    const marks = values.map(() => "?").join(", ");
    const row = REFERENCE_CLOCK.prepare(`SELECT strftime(${marks}) AS value`).get(...values);
    return row?.value ?? null;
  });
}

export class SqliteD1 {
  readonly sqlite = new DatabaseSync(":memory:");
  readonly prepared: string[] = [];
  readonly sessions: unknown[] = [];
  writeBatches = 0;
  #writeGate: (() => Promise<void>) | null = null;
  #writeFailure: Error | null = null;
  #readFailure: { error: Error; skip: number } | null = null;

  constructor(skipMigrations: readonly string[] = []) {
    const omitted = new Set(skipMigrations);
    for (const file of readdirSync(MIGRATIONS_DIR).sort()) {
      if (omitted.has(file)) continue;
      this.sqlite.exec(readFileSync(resolve(MIGRATIONS_DIR, file), "utf8"));
    }
  }

  // Each write batch waits until `count` write batches are waiting.
  holdWritesUntil(count: number): void {
    let waiting = 0;
    let release: () => void = () => {};
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.#writeGate = async () => {
      waiting += 1;
      if (waiting === count) {
        release();
      }
      await released;
    };
  }

  // The next write batch throws this error and writes nothing.
  failNextWrite(error: Error): void {
    this.#writeFailure = error;
  }

  // The read batch after `skip` successful read batches throws this error.
  failRead(error: Error, skip = 0): void {
    this.#readFailure = { error, skip };
  }

  binding(): D1Database {
    const refuse = (): never => {
      throw new Error("owner-lock access must use withSession");
    };
    const database = {
      prepare: refuse,
      batch: refuse,
      exec: refuse,
      dump: refuse,
      withSession: (constraint?: unknown) => {
        this.sessions.push(constraint);
        return this.#session();
      },
    };
    return database as unknown as D1Database;
  }

  #session(): D1DatabaseSession {
    const session = {
      prepare: (sql: string) => {
        this.prepared.push(sql);
        return statement({ sql, values: [] });
      },
      batch: (statements: unknown[]) =>
        this.#batch(statements as unknown as Statement[]),
      getBookmark: () => null,
    };
    return session as unknown as D1DatabaseSession;
  }

  async #batch(statements: Statement[]): Promise<D1Result[]> {
    for (const s of statements) {
      // D1 refuses a bind list that does not fill every ?N. SQLite binds NULL.
      const count = Math.max(0, ...[...s.sql.matchAll(/\?(\d+)/g)].map((m) => Number(m[1])));
      if (s.values.length !== count) {
        throw new Error("D1_ERROR: Wrong number of parameter bindings for SQL query.");
      }
      // D1 refuses a statement that binds more than 100 parameters. SQLite allows far more.
      if (s.values.length > 100) {
        throw new Error("D1_ERROR: too many SQL variables");
      }
    }

    const writes = statements.some((s) => !isRead(s.sql));
    if (!writes && this.#readFailure !== null) {
      if (this.#readFailure.skip === 0) {
        const failure = this.#readFailure.error;
        this.#readFailure = null;
        throw failure;
      }
      this.#readFailure.skip -= 1;
    }
    if (writes) {
      this.writeBatches += 1;
      if (this.#writeGate !== null) {
        await this.#writeGate();
      }
      if (this.#writeFailure !== null) {
        const failure = this.#writeFailure;
        this.#writeFailure = null;
        throw failure;
      }
    }

    // D1 runs a batch as one transaction and rolls it back on any error.
    this.sqlite.exec("BEGIN");
    try {
      const results = statements.map((s) => {
        const prepared = this.sqlite.prepare(s.sql);
        let rows: unknown[] = [];
        if (isRead(s.sql)) {
          rows = prepared.all(...s.values);
        } else {
          prepared.run(...s.values);
        }
        return { success: true, meta: {}, results: rows } as unknown as D1Result;
      });
      this.sqlite.exec("COMMIT");
      return results;
    } catch (error) {
      this.sqlite.exec("ROLLBACK");
      throw error;
    }
  }
}

// PRAGMA table_info is the D1 schema probe. It returns rows and does not write.
function isRead(sql: string): boolean {
  return /^\s*SELECT\b/i.test(sql) || /^\s*PRAGMA\s+table_info\b/i.test(sql);
}

function statement(state: Statement): D1PreparedStatement {
  const bound = {
    ...state,
    bind: (...values: unknown[]) =>
      statement({ sql: state.sql, values: values as SQLInputValue[] }),
  };
  return bound as unknown as D1PreparedStatement;
}
