/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Per-item authority envelope, docs/design/authority-envelope.md. The envelope
 * is the item's touch list and a denial record. It is not an approval, a
 * credential, or a provider's step plan. Basic stores every flag false, and no
 * input or owner path sets one true. This module does not fetch, resolve a
 * name, or log.
 */

/** Every authority flag, sorted by code point. A stored Basic envelope names each one as false. */
export const AUTHORITY_FLAGS = [
  "additional_tools",
  "credential_creation",
  "credentials",
  "delegation",
  "external_actions",
  "message_grants_authority",
  "private_resources",
  "resource_labels_grant_access",
  "spending",
] as const;

export type AuthorityFlag = (typeof AUTHORITY_FLAGS)[number];

/** Fixed audit reasons. A reason names a rule. It never carries input text. */
export type EnvelopeReason =
  | "unknown_key"
  | "wrong_type"
  | "duplicate"
  | "over_limit"
  | "non_canonical_url"
  | "bad_label"
  | "flag_not_false"
  | "digest_mismatch"
  | "citation_mismatch"
  | "missing_envelope";

/** The one canonical stored document. `contract_version` and `limits` are server constants. */
export interface Envelope {
  authority: Record<AuthorityFlag, false>;
  contract_version: 1;
  limits: { max_answer_chars: 800; max_resources: 3; max_sources: 3 };
  scope: { allowed_resources: string[]; allowed_sources: string[] };
}

export type BuiltEnvelope = { ok: true; json: string; envelope: Envelope } | { ok: false; reason: EnvelopeReason };

/** A stored row read back. `missing` is a pre-envelope row: null is not an empty allow-list. */
export type StoredEnvelope =
  | { status: "valid"; envelope: Envelope; sha256: string }
  | { status: "missing" }
  | { status: "invalid"; reason: "digest_mismatch" | "flag_not_false" };

/** Where a repeated object key sits in an MCP message. See repeatedKeys. */
export type RepeatedKeys = "none" | "envelope" | "message" | "malformed";

const MAX_SOURCES = 3;
const MAX_RESOURCES = 3;
const MAX_ANSWER_CHARS = 800;
const MAX_SOURCE_CODE_POINTS = 300;
const SCOPE_KEYS: readonly string[] = ["allowed_resources", "allowed_sources"];
const FLAGS: readonly string[] = AUTHORITY_FLAGS;

// C0/C1 controls except tab/newline, lone surrogates, and invisible text controls.
const HIDDEN = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f؜​‎‏‪-‮⁠-⁤⁦-⁩﻿\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}\ud800-\udfff]/u;
const GROK_TOKEN = /admrn_gb_[A-Za-z0-9_-]{43}/;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9 .:_-]{0,79}$/;
const DNS = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z](?:[a-z0-9-]*[a-z0-9])?$/;
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
const DIGEST = /^[0-9a-f]{64}$/;
// The only non-public host list. It reads the name as written and resolves nothing.
const NON_PUBLIC_SUFFIXES = [".localhost", ".local", ".internal", ".invalid"];

function plainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function byCodePoint(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Item text rules: not blank, at most `max` code points, no hidden text, no Grok-token-shaped string. */
export function isItemText(value: unknown, max: number): value is string {
  return typeof value === "string" && value.trim() !== "" && [...value].length <= max
    && !HIDDEN.test(value) && !GROK_TOKEN.test(value);
}

function percentCanonical(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== "%") continue;
    const hex = value.slice(index + 1, index + 3);
    if (!/^[0-9A-F]{2}$/.test(hex) || UNRESERVED.test(String.fromCharCode(Number.parseInt(hex, 16)))) return false;
    index += 2;
  }
  return true;
}

function markHasBody(value: string, mark: "?" | "#"): boolean {
  const at = value.indexOf(mark);
  return at === -1 || at < value.length - 1;
}

/**
 * The one grammar for `allowed_sources` and result citations. Syntax only: a
 * passing string is still a reference the sender wrote. It does not show that
 * the host is public, and nothing here resolves or fetches it.
 */
export function isCanonicalSource(value: unknown): value is string {
  if (!isItemText(value, MAX_SOURCE_CODE_POINTS)) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  // A spelling the parser would rewrite fails here. That is the hostname normalisation check.
  if (url.href !== value || url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.port !== "") return false;
  const host = url.hostname;
  if (!DNS.test(host) || host.split(".").some((label) => label.length > 63)) return false;
  if (host === "localhost" || NON_PUBLIC_SUFFIXES.some((suffix) => host.endsWith(suffix))) return false;
  return percentCanonical(value) && markHasBody(value, "?") && markHasBody(value, "#");
}

/** A label names something. It selects no row, credential, key, resource, or file. */
function isLabel(value: string): boolean {
  return LABEL.test(value) && value === value.trim() && !GROK_TOKEN.test(value);
}

type Listed = { ok: true; values: string[] } | { ok: false; reason: EnvelopeReason };

function sortedList(value: unknown, cap: number, valid: (entry: string) => boolean, invalid: EnvelopeReason): Listed {
  if (!Array.isArray(value)) return { ok: false, reason: "wrong_type" };
  const entries: unknown[] = value;
  if (!entries.every((entry): entry is string => typeof entry === "string")) return { ok: false, reason: "wrong_type" };
  if (entries.length > cap) return { ok: false, reason: "over_limit" };
  if (!entries.every(valid)) return { ok: false, reason: invalid };
  // Duplicates reject the call. The server does not drop one and continue.
  if (new Set(entries).size !== entries.length) return { ok: false, reason: "duplicate" };
  return { ok: true, values: [...entries].sort(byCodePoint) };
}

/**
 * Validate a caller-supplied `scope` and optional `authority`, then build the
 * one canonical JSON text. A flag may be omitted or sent as false. Anything
 * else rejects the whole envelope, and nothing from a rejected envelope is kept.
 */
export function buildEnvelope(scope: unknown, authority: unknown): BuiltEnvelope {
  if (!plainObject(scope)) return { ok: false, reason: "wrong_type" };
  let flags: Record<string, unknown> = {};
  if (authority !== undefined) {
    if (!plainObject(authority)) return { ok: false, reason: "wrong_type" };
    flags = authority;
  }
  if (Object.keys(scope).some((key) => !SCOPE_KEYS.includes(key))) return { ok: false, reason: "unknown_key" };
  if (Object.keys(flags).some((key) => !FLAGS.includes(key))) return { ok: false, reason: "unknown_key" };
  for (const flag of FLAGS) {
    const value = flags[flag];
    if (value === undefined || value === false) continue;
    return { ok: false, reason: value === true ? "flag_not_false" : "wrong_type" };
  }
  const sources = sortedList(scope.allowed_sources, MAX_SOURCES, isCanonicalSource, "non_canonical_url");
  if (!sources.ok) return sources;
  const resources = sortedList(scope.allowed_resources, MAX_RESOURCES, isLabel, "bad_label");
  if (!resources.ok) return resources;
  const envelope: Envelope = {
    authority: {
      additional_tools: false,
      credential_creation: false,
      credentials: false,
      delegation: false,
      external_actions: false,
      message_grants_authority: false,
      private_resources: false,
      resource_labels_grant_access: false,
      spending: false,
    },
    contract_version: 1,
    limits: { max_answer_chars: MAX_ANSWER_CHARS, max_resources: MAX_RESOURCES, max_sources: MAX_SOURCES },
    scope: { allowed_resources: resources.values, allowed_sources: sources.values },
  };
  return { ok: true, json: JSON.stringify(envelope), envelope };
}

/** Lowercase hex SHA-256 of the UTF-8 bytes. */
export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * The read path for every stored row: hash the stored text, compare it to the
 * column, parse it, rebuild it, and require the rebuilt bytes to equal the
 * stored bytes. Malformed JSON and any other difference are digest_mismatch.
 */
export async function checkStoredEnvelope(json: string | null, sha256: string | null): Promise<StoredEnvelope> {
  if (json === null && sha256 === null) return { status: "missing" };
  if (json === null || sha256 === null || !DIGEST.test(sha256) || await sha256Hex(json) !== sha256) {
    return { status: "invalid", reason: "digest_mismatch" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return { status: "invalid", reason: "digest_mismatch" };
  }
  if (!plainObject(parsed)) return { status: "invalid", reason: "digest_mismatch" };
  const authority = parsed.authority;
  if (plainObject(authority) && FLAGS.some((flag) => authority[flag] !== undefined && authority[flag] !== false)) {
    return { status: "invalid", reason: "flag_not_false" };
  }
  const rebuilt = buildEnvelope(parsed.scope, authority);
  if (!rebuilt.ok || rebuilt.json !== json) return { status: "invalid", reason: "digest_mismatch" };
  return { status: "valid", envelope: rebuilt.envelope, sha256 };
}

const JSON_SPACE = new Set([" ", "\t", "\n", "\r"]);
const JSON_ESCAPES = new Map([["\"", "\""], ["\\", "\\"], ["/", "/"], ["b", "\b"], ["f", "\f"], ["n", "\n"], ["r", "\r"], ["t", "\t"]]);
const ENVELOPE_FIELDS: readonly string[] = ["scope", "authority"];

function readString(text: string, start: number): { value: string; end: number } | null {
  let value = "";
  let index = start + 1;
  let chunk = index;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code === 0x22) return { value: value + text.slice(chunk, index), end: index + 1 };
    if (code < 0x20) return null;
    if (code !== 0x5c) {
      index += 1;
      continue;
    }
    value += text.slice(chunk, index);
    const escape = text.charAt(index + 1);
    if (escape === "u") {
      const hex = text.slice(index + 2, index + 6);
      if (!/^[0-9A-Fa-f]{4}$/.test(hex)) return null;
      // Each escape is one UTF-16 unit, so a surrogate pair decodes to one code point.
      value += String.fromCharCode(Number.parseInt(hex, 16));
      index += 6;
    } else {
      const decoded = JSON_ESCAPES.get(escape);
      if (decoded === undefined) return null;
      value += decoded;
      index += 2;
    }
    chunk = index;
  }
  return null;
}

function scalarEnd(text: string, start: number): number {
  for (const literal of ["true", "false", "null"]) {
    if (text.startsWith(literal, start)) return start + literal.length;
  }
  let end = start;
  while (end < text.length && "0123456789+-.eE".includes(text.charAt(end))) end += 1;
  return end;
}

interface Container {
  /** Decoded keys seen so far. Null for an array. */
  keys: Set<string> | null;
  /** Inside params.arguments.scope or params.arguments.authority. */
  envelope: boolean;
  /** Object key path from the root, kept only while it can still reach params.arguments. */
  path: readonly string[] | null;
  /** The key whose value is being read. */
  key: string;
}

function atArguments(path: readonly string[] | null): boolean {
  return path !== null && path.length === 2 && path[0] === "params" && path[1] === "arguments";
}

/**
 * Find repeated object keys in a JSON text before JSON.parse keeps only the
 * last copy. Keys compare after string unescaping, so "a" and "a" are one
 * key. "envelope" means every repeat is inside params.arguments.scope or
 * params.arguments.authority, or repeats one of those two keys. "message" means
 * a repeat anywhere else. "malformed" leaves the verdict to JSON.parse.
 */
export function repeatedKeys(text: string): RepeatedKeys {
  const stack: Container[] = [];
  let verdict: "none" | "envelope" | "message" = "none";
  let expect: "value" | "key" | "colon" | "after" = "value";
  // Directly after an opening bracket, the matching close is allowed.
  let closable = false;
  let index = 0;
  for (;;) {
    while (index < text.length && JSON_SPACE.has(text.charAt(index))) index += 1;
    const top = stack.at(-1);
    if (index >= text.length) return expect === "after" && top === undefined ? verdict : "malformed";
    const char = text.charAt(index);
    if (expect === "after") {
      if (top === undefined) return "malformed";
      if (char === ",") {
        expect = top.keys === null ? "value" : "key";
        closable = false;
      } else if (char === (top.keys === null ? "]" : "}")) {
        stack.pop();
      } else {
        return "malformed";
      }
      index += 1;
      continue;
    }
    if (expect === "colon") {
      if (char !== ":") return "malformed";
      expect = "value";
      closable = false;
      index += 1;
      continue;
    }
    if (expect === "key") {
      if (top === undefined || top.keys === null) return "malformed";
      if (char === "}" && closable) {
        stack.pop();
        expect = "after";
        index += 1;
        continue;
      }
      if (char !== "\"") return "malformed";
      const key = readString(text, index);
      if (key === null) return "malformed";
      if (top.keys.has(key.value)) {
        const envelope = top.envelope || (atArguments(top.path) && ENVELOPE_FIELDS.includes(key.value));
        if (!envelope) verdict = "message";
        else if (verdict === "none") verdict = "envelope";
      }
      top.keys.add(key.value);
      top.key = key.value;
      expect = "colon";
      index = key.end;
      continue;
    }
    if (char === "]" && closable && top !== undefined && top.keys === null) {
      stack.pop();
      expect = "after";
      index += 1;
      continue;
    }
    if (char === "{" || char === "[") {
      const inObject = top !== undefined && top.keys !== null;
      const envelope = top === undefined ? false
        : inObject ? top.envelope || (atArguments(top.path) && ENVELOPE_FIELDS.includes(top.key)) : top.envelope;
      let path: readonly string[] | null = null;
      if (char === "{") {
        if (top === undefined) path = [];
        else if (inObject && top.path !== null && top.path.length < 2) path = [...top.path, top.key];
      }
      stack.push({ keys: char === "{" ? new Set<string>() : null, envelope, path, key: "" });
      expect = char === "{" ? "key" : "value";
      closable = true;
      index += 1;
      continue;
    }
    if (char === "\"") {
      const value = readString(text, index);
      if (value === null) return "malformed";
      expect = "after";
      index = value.end;
      continue;
    }
    const end = scalarEnd(text, index);
    if (end === index) return "malformed";
    expect = "after";
    index = end;
  }
}
