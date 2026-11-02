/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Fails when a documented item-deadline default disagrees with src/provisional.ts.
 * llms.txt and docs/llms.txt must be byte-identical.
 */

import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

export const CLAIM_ORIGIN_SENTENCE = "`POST /owner/claim` returns 500 `internal_error` when `BRIDGE_ORIGIN` is unset or invalid, and 404 `not_found` when the request URL's origin is not `BRIDGE_ORIGIN`. It always refuses `Origin: null`. Otherwise a supplied `Origin` must equal `BRIDGE_ORIGIN`, and a request without `Origin` requires `Sec-Fetch-Site` to be absent or `same-origin`.";

const REQUIRED_SENTENCE = ["README.md", "llms.txt"];

export function readDeadlineConstants(source) {
  function constant(name) {
    const match = source.match(new RegExp(`export const ${name} = (\\d+);`));
    if (!match) throw new Error(`missing ${name}`);
    return match[1];
  }
  return {
    min: constant("ITEM_DEADLINE_MIN_MINUTES"),
    max: constant("ITEM_DEADLINE_MAX_MINUTES"),
    deadlineDefault: constant("ITEM_DEADLINE_DEFAULT_MINUTES"),
  };
}

export function deadlineSentence(constants) {
  return `\`deadline_minutes\` is an integer from ${constants.min} to ${constants.max} and defaults to ${constants.deadlineDefault}.`;
}

export function checkDeadlineText(file, text, constants) {
  const failures = [];
  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!/deadline/i.test(line)) continue;
    for (const match of line.matchAll(/defaults to (\d+)/g)) {
      if (match[1] !== constants.deadlineDefault) {
        failures.push(`${file}:${index + 1}: defaults to ${match[1]}, code default is ${constants.deadlineDefault}`);
      }
    }
    for (const match of line.matchAll(/from (\d+) to (\d+)/g)) {
      if (match[1] !== constants.min || match[2] !== constants.max) {
        failures.push(`${file}:${index + 1}: range ${match[1]} to ${match[2]}, code is ${constants.min} to ${constants.max}`);
      }
    }
    for (const match of line.matchAll(/\bdefault(?: is)? (\d+)/g)) {
      if (match[1] !== constants.deadlineDefault) {
        failures.push(`${file}:${index + 1}: default ${match[1]}, code default is ${constants.deadlineDefault}`);
      }
    }
  }
  return failures;
}

function markdownFiles(directory) {
  if (!existsSync(directory)) return [];
  const found = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      found.push(...markdownFiles(path));
    } else if (entry.isFile() && entry.name.endsWith(".md")) {
      found.push(path);
    }
  }
  return found;
}

function trackedDocs(root) {
  const files = [
    join(root, "README.md"),
    join(root, "llms.txt"),
    join(root, "CHANGELOG.md"),
    ...markdownFiles(join(root, "docs")),
    ...markdownFiles(join(root, "templates", "grok-bot")),
  ];
  return files.filter((path) => existsSync(path));
}

export function checkRepository(root) {
  const source = readFileSync(join(root, "src", "provisional.ts"), "utf8");
  const constants = readDeadlineConstants(source);
  const sentence = deadlineSentence(constants);
  const failures = [];
  const pointerPath = join(root, "docs", "llms.txt");
  const pointer = existsSync(pointerPath) ? readFileSync(pointerPath, "utf8") : "";
  if (pointer !== readFileSync(join(root, "llms.txt"), "utf8")) {
    failures.push("docs/llms.txt must be byte-identical to llms.txt");
  }
  for (const file of ["docs/install.md", "docs/test-instance.md"]) {
    const path = join(root, file);
    if (!existsSync(path) || !readFileSync(path, "utf8").includes(CLAIM_ORIGIN_SENTENCE)) {
      failures.push(file + " is missing the POST /owner/claim Origin rule");
    }
  }
  for (const file of REQUIRED_SENTENCE) {
    const path = join(root, file);
    const text = existsSync(path) ? readFileSync(path, "utf8") : "";
    if (!text.includes(sentence)) failures.push(`${file} is missing the deadline sentence from src/provisional.ts`);
  }
  const instructions = join(root, "templates", "grok-bot", "instructions.md");
  if (existsSync(instructions) && !readFileSync(instructions, "utf8").includes(sentence)) {
    failures.push("templates/grok-bot/instructions.md is missing the deadline sentence from src/provisional.ts");
  }
  for (const path of trackedDocs(root)) {
    const file = relative(root, path);
    if (file === "docs/llms.txt") continue;
    failures.push(...checkDeadlineText(file, readFileSync(path, "utf8"), constants));
  }
  return failures;
}

function main() {
  const failures = checkRepository(ROOT);
  if (failures.length > 0) {
    process.stderr.write(`${failures.join("\n")}\n`);
    process.exit(1);
  }
  process.stdout.write("checked documented defaults against src/provisional.ts\n");
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) main();
