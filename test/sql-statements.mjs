/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Split a SQL script into statements for drivers that prepare one statement
 * at a time. Semicolons inside CREATE TRIGGER bodies stay with the trigger.
 */

/**
 * @param {string} script
 * @returns {string[]}
 */
export function sqlStatements(script) {
  const source = script.replace(/--[^\n]*/g, "");
  const statements = [];
  const marker = /\bBEGIN\b|\bEND\b|;/gi;
  let depth = 0;
  let start = 0;
  for (const match of source.matchAll(marker)) {
    const token = match[0].toUpperCase();
    const index = match.index ?? 0;
    if (token === "BEGIN") {
      depth += 1;
      continue;
    }
    if (token === "END") {
      if (depth > 0) depth -= 1;
      continue;
    }
    if (depth === 0) {
      const statement = source.slice(start, index).trim();
      if (statement) statements.push(statement);
      start = index + match[0].length;
    }
  }
  const tail = source.slice(start).trim();
  if (tail) statements.push(tail);
  return statements;
}
