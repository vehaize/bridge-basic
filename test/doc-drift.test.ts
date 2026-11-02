/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  CLAIM_ORIGIN_SENTENCE,
  checkDeadlineText,
  checkRepository,
  deadlineSentence,
  readDeadlineConstants,
} from "../scripts/doc-drift.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts/doc-drift.mjs");

describe("documented deadline defaults", () => {
  it("matches deadline defaults, mirrored llms.txt, and the strict claim Origin rule", () => {
    const constants = readDeadlineConstants(readFileSync(join(ROOT, "src/provisional.ts"), "utf8"));
    assert.equal(constants.min, "5");
    assert.equal(constants.deadlineDefault, "360");
    assert.equal(constants.max, "1440");
    assert.deepEqual(checkRepository(ROOT), []);
    assert.equal(readFileSync(join(ROOT, "docs/llms.txt"), "utf8"), readFileSync(join(ROOT, "llms.txt"), "utf8"));
    for (const file of ["docs/install.md", "docs/test-instance.md"]) {
      assert.ok(readFileSync(join(ROOT, file), "utf8").includes(CLAIM_ORIGIN_SENTENCE));
    }
    const result = spawnSync(process.execPath, [SCRIPT], { cwd: ROOT, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "checked documented defaults against src/provisional.ts\n");
  });

  it("rejects a deadline line that states a different default or range", () => {
    const constants = readDeadlineConstants(readFileSync(join(ROOT, "src/provisional.ts"), "utf8"));
    const wrongDefault = checkDeadlineText(
      "sample.md",
      "`deadline_minutes` is an integer from 5 to 1440 and defaults to 60.\n",
      constants,
    );
    assert.equal(wrongDefault.length, 1);
    assert.match(wrongDefault[0], /defaults to 60/);
    const wrongRange = checkDeadlineText(
      "sample.md",
      "The deadline_minutes range is from 5 to 60.\n",
      constants,
    );
    assert.equal(wrongRange.length, 1);
    assert.match(wrongRange[0], /range 5 to 60/);
    const unrelated = checkDeadlineText("sample.md", "The limit defaults to 60.\n", constants);
    assert.deepEqual(unrelated, []);
    assert.deepEqual(checkDeadlineText("sample.md", `${deadlineSentence(constants)}\n`, constants), []);
  });
});
