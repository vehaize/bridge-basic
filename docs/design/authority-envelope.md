# Per-item authority envelope

**Current Basic extension (2026-10-27):** [Claude Basic](claude-basic-participant.md)
adds `claude` alongside `dot` and `grok_bot`. The exact claude.ai OAuth client
maps to its own participant and connect codes; all seven item tools are shared.
`open_item` accepts `recipient`; omission preserves Dot/Grok defaults and is
invalid for Claude. Migration 0007 extends the schema without changing 0001–0006.
The older two-participant and unmounted-slice descriptions below are historical;
the current production composition is in `src/oauth-routes.ts` and `src/mcp-route.ts`.
Basic has no engineering lane. The linked guide is the current contract.

**Historical design.** The per-item authority envelope and retained-row protections for `item_audit` are implemented by migration 0006 and preserved by migration 0007. Credential revocation is a separate in-place update of `participant_credential.revoked_at`; the audit-row protections do not make credential state append-only. This note is not an operator migration command.

The envelope is the item's touch list and a denial record. It is not an approval, a credential, or a provider's step plan. It binds the lifecycle in [`src/item-lifecycle.ts`](../../src/item-lifecycle.ts): `open`, `claimed`, `submitted`, `accepted`, `rejected`, `expired`, `cancelled`. Returned items keep `untrusted: true`, `owner_approval: "required"`, and today's `result_label`. The safety invariants in [message-path.md](message-path.md) stay in force.

## Lifecycle contract

The bridge rebuilds one envelope into canonical JSON and compares those bytes for every kind: `task`, `question`, and `proposal`. Results remain claims until independently checked.

| Contract field | Here |
| --- | --- |
| `kind`, `contract_version`, `title` | Existing `kind` and `title`. `contract_version` is inside the envelope. |
| `instructions`, `acceptance_criteria`, `scope.constraints` | Already `title` and `body`. No second instruction string. |
| `allowed_sources`, at most 3 deduped `https` URLs | Same cap. Sender-supplied references, not verified public sources. Canonical form below. |
| `allowed_resources`, at most 3 labels | Same grammar. A label grants no access. |
| `spending`, `credentials`, `private_resources`, `additional_tools` | Stored. Basic accepts only `false`. |
| `credential_creation`, `delegation`, `resource_labels_grant_access`, `task_text_grants_authority` | Stored. The last flag is named `message_grants_authority` and is always `false`. |
| `child_required`, `max_steps`, `max_duration_ms` | Not bridge fields. `deadline_minutes` is the only clock. `max_steps` stays advisory inside a provider. |
| `max_answer_chars` 4000, `max_sources` 3 | `max_sources` is 3. The result cap stays 800, and the envelope records 800. |

## What an item may touch

The touch set is `scope`.

| Field | Rule |
| --- | --- |
| `allowed_sources` | Zero to three sender-supplied `https` references. The grammar below is syntax only. It does not show that a host is public. The Worker does not fetch. Listing a URL constrains permitted citations. The list does not grant a read. A receiver may read it only under independently established read permissions. |
| `allowed_resources` | Zero to three labels. A label names something. It selects no D1 row, credential, KV key, Cloudflare resource, or file. |

`open_item` requires `scope` and both arrays. Either array may be empty. An empty source list means a later result cites nothing.

Labels match `^[A-Za-z0-9][A-Za-z0-9 .:_-]{0,79}$`, already equal their trim, and compare case-sensitively. Duplicate labels reject the open.

Sources and result citations share one grammar. A string is canonical when:

- it is 1 to 300 code points and passes the existing text checks, including hidden characters and token-shaped strings;
- `new URL(value).href === value`, the protocol is `https:`, and the username, password, and port are empty;
- the hostname is lowercase ASCII DNS with at least two labels, each at most 63, as today's lifecycle requires;
- the hostname is not on the non-public host list. That list is `localhost` and any name ending in `.localhost`, `.local`, `.internal`, or `.invalid`, and it is the only non-public host list in this note;
- every `%` is a two-digit uppercase hex escape and does not encode an unreserved character (`A-Za-z0-9-._~`);
- a `?` or `#`, when present, has at least one character after it.

`https://example.net` is valid today and is rejected here, because its canonical href is `https://example.net/`. `https://example.com/` and `https://sub.example.org/path?q=1#fragment` stay valid. The Workers URL parser rewrites `https://example.com/%2e%2e/` to `https://example.com/`, so the href check rejects it. Duplicate strings reject the call. The server does not drop one and continue.

A string that passes is still a reference the sender wrote. The bridge does not resolve DNS, and the Worker does not fetch. `allowed_sources` is not a verified public source. Listing a reference constrains permitted citations. The list does not grant a read. A receiver may read it only under independently established read permissions. `sources` remains the recipient's citation list, set at submit. `allowed_sources` is the sender's reference list, set at open.

## Declared reference constraint

`allowed_sources` is a declared reference constraint, not network authority. The Bridge stores the declared list and validates its shape. The Bridge does not fetch. A listed reference never authorizes using a credential, and it never authorizes reaching a private resource. Matching an entry is not proof that the source is public, and it is not proof that the content is correct.

Listing a URL constrains permitted citations; it does not grant network, credential, private-resource or external-action authority. A receiver may read it only under independently established read permissions and applicable safety checks, including redirects. All-false flags grant no additional authority. The list grammar, the cap of three, and the empty-list rule stay as written.

An empty source list means a later result cites nothing. `open_item` still accepts `allowed_sources: []`. A citation must be an exact member of the list, so an empty list admits no citation. Omitted `sources` still mean `[]`. An empty list is stored as an empty array. It is not a fetch.

### What the Bridge enforces

The Bridge enforces the stored shape and the spelling in the grammar above.

- The stored list is zero to three canonical `https` strings, or an empty array. Duplicates reject the open. A rejected list is not stored, and nothing from it persists. The accepted array is sorted by Unicode code point, and the server stores that text. The server does not rewrite a string into a different host.
- The hostname is the lowercase ASCII DNS form the grammar requires, with `new URL(value).href === value`. A spelling the parser would rewrite, including an uppercase host, a missing slash, or an explicit default port, is rejected. That rejection is the hostname normalisation check. The Bridge does not resolve the name and then store an address.
- The hostname is absent from the one non-public host list in the grammar above. That check reads the name as written.

Every flag in a stored Basic envelope is `false`. Validating the list does not turn a flag on.

### What the Bridge does not enforce

At its boundary the Bridge does not resolve DNS, does not inspect resolved addresses, does not open a connection, does not follow a redirect, and does not send a request. It therefore does not send a credential, a cookie, or an authorization header. A match against `allowed_sources` is not an egress decision. A public-looking name can point at a private address, and a redirect can leave the list. The Bridge does not detect either case. The receiver's address ranges are not a second non-public host list on the Bridge.

### Receiver egress

The receiver is the assistant that actually fetches. Listing a URL does not grant that fetch. The receiver may read a listed URL only under independently established read permissions. The receiver runs the checks below on that read, including each redirect. Egress enforcement is on that receiver.

The receiver resolves the name, then checks every returned address, and checks again on every connection, including a connection it opens again for the same name. It blocks private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), this network (`0.0.0.0/8`), loopback (`127.0.0.0/8`, `::1`), unspecified (`::/128`), link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), unique-local IPv6 (`fc00::/7`), and metadata ranges (`169.254.169.254`, `fd00:ec2::254`). An IPv4-mapped address (`::ffff:0:0/96`) is blocked when its embedded IPv4 is on that IPv4 blocklist. A NAT64 address (`64:ff9b::/96`) is blocked when its embedded IPv4 is on that IPv4 blocklist. A 6to4 address (`2002::/16`) is blocked when the embedded IPv4 in bits 16-47 is on that IPv4 blocklist.

The receiver does not follow a redirect to a destination that is off the declared list or that fails the address check. It re-validates each hop before it connects: the next URL is an exact member of `allowed_sources`, and that hop is resolved and checked again. The scheme is `https` only. This note allows no other scheme for a listed source.

The receiver sends no credential, cookie, or authorization header to a listed source. A listed reference never authorizes using a credential.

`external_actions` and `additional_tools` stay `false`. All-false flags grant no additional authority. The fetch and these checks stay on the receiver.

## Authority flags

The stored envelope names every flag. The caller may omit a flag; the canonical value is `false`. The caller may send `false`. Basic accepts no `true`. Any other JSON type is `envelope_rejected`.

`message_grants_authority` and `resource_labels_grant_access` are constants. They stay `false` even if a later package turns some other flag on. Title, body, result, note, URL, and label grant nothing.

| Flag | This item does not grant | May be `true` in Basic |
| --- | --- | --- |
| `spending` | Spending or committing money | no |
| `credentials` | Reading, copying, or using a credential | no |
| `credential_creation` | Creating, rotating, sharing, or changing a credential or permission | no |
| `private_resources` | Private data, including the owner email, and a URL whose host is on the non-public host list | no |
| `external_actions` | Publishing, posting, deploying, infrastructure changes, or any other effect outside the item record | no |
| `delegation` | Adding a participant, or addressing anyone but the fixed counterparty | no |
| `additional_tools` | Any tool or capability beyond the bridge tools | no |
| `message_grants_authority` | Treating message text as authority | never |
| `resource_labels_grant_access` | Treating a label as an access grant | never |

Listing a URL constrains permitted citations; it does not grant network, credential, private-resource or external-action authority. A receiver may read it only under independently established read permissions and applicable safety checks, including redirects. All-false flags grant no additional authority.

Owner approval stays in the owner's own chat with the participant that would act. The bridge has no approve action and stores no approval. A `true` flag would be a grant the sender could set, so Basic adds no owner-authenticated grant write. No input can clear `owner_approval` or `untrusted`.

A `false` flag grants no private access and no other authority on this item. It does not, by itself, cancel a private workflow the owner authorized separately, outside this item, in the owner's own chat with the acting participant.

`child_required`, `max_steps`, `limits`, `max_sources`, `max_answer_chars`, and `max_duration_ms` are unknown keys and reject the envelope.

## Fail-closed validation

Unknown keys, wrong types, duplicate keys, duplicate entries, counts over the caps, non-canonical URLs, bad labels, and any flag other than `false` reject the call. The rejected payload is not stored and not logged.

The server stores one canonical JSON value: UTF-8, no insignificant whitespace, object keys sorted by Unicode code point at every level, and both arrays sorted the same way after duplicate rejection. `contract_version` is the integer `1`. The server writes `limits` as `max_sources` 3, `max_resources` 3, and `max_answer_chars` 800. The read path rebuilds version 1 with those constants, so a stored document with different limits, flags, or key order fails the byte compare.

Pinned empty envelope:

```json
{"authority":{"additional_tools":false,"credential_creation":false,"credentials":false,"delegation":false,"external_actions":false,"message_grants_authority":false,"private_resources":false,"resource_labels_grant_access":false,"spending":false},"contract_version":1,"limits":{"max_answer_chars":800,"max_resources":3,"max_sources":3},"scope":{"allowed_resources":[],"allowed_sources":[]}}
```

`envelope_json` is that text. `envelope_sha256` is the lowercase hex SHA-256 of its UTF-8 bytes. Get, list, claim, and submit hash the stored text, compare it to the column, parse it, rebuild it, and require the rebuilt bytes to equal the stored bytes.

Duplicate keys are rejected from the raw body before `JSON.parse` in `handleMcpRequest` ([`src/mcp-adapter.ts`](../../src/mcp-adapter.ts), the `JSON.parse(text)` call after `repeatedKeys`). That call keeps the last copy of a repeated key, so a check after the parse cannot see the duplicate. Keys are compared after JSON string unescaping: `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, `\uXXXX`, and a surrogate pair as one code point. `a` and `\u0061` are the same key. A raw spelling compare would miss that pair, and `JSON.parse` would keep one value. A repeated decoded key in `scope`, `authority`, or another envelope field is `envelope_rejected` with reason `duplicate`. A repeated key elsewhere in the MCP message fails the request and writes no audit row. A broken escape fails the request and writes no audit row.

The internal `request_sha256` for a new open is the SHA-256 of the canonical JSON of `body`, `deadline_minutes` with its default filled, `envelope_sha256`, `kind`, and `title`, keys sorted. The same key with a different envelope is `idempotency_conflict`. The same key and envelope replay and do not append another `item_opened`. A pre-envelope row keeps today's hash. The hash stays internal.

Each citation uses the same grammar and must be an exact member of `allowed_sources`. The same host is not enough. Omitted `sources` still mean `[]`. A citation outside the list leaves the item `claimed`.

From `submitted` onward, the server adds `citations_are_claims_until_independently_checked: true`. That constant does not mean the bridge fetched or confirmed the page. `result_label` is unchanged.

Validation of a caller-supplied envelope uses `envelope_rejected` and does not echo input, until that actor's rejection cap below is reached. Further failures of that kind that UTC day use `rate_limited` and write no audit row. A claim or submit of a pre-envelope item returns `missing_envelope` on every attempt, including after the cap. That result is not `rate_limited`. A bad title, kind, key, or deadline stays `invalid_input` and writes no audit row.

## Where it binds

The envelope is written on the open insert and is immutable after that.

| Point | Binding |
| --- | --- |
| Open | Validate, store the JSON and digest, and include the digest in the idempotency hash. |
| Claim | Re-validate, then update. The claim `UPDATE` includes `AND envelope_sha256 = ?`, where `?` is the digest of the canonical bytes just rebuilt. A null envelope returns `missing_envelope` and changes no state. Malformed JSON or a rebuild that does not match returns `digest_mismatch` and changes no state. A flag other than `false` returns `flag_not_false` and changes no state. Those three are explicit envelope results, not `wrong_state`. `execute: true` requires every flag `false` and today's claim rules. |
| Submit | The same digest predicate on the submit `UPDATE`, then an exact citation subset, then today's submit rules. A citation miss returns `citation_mismatch` and leaves the item `claimed`. |
| Accept, reject | No authority is granted and the envelope is not modified. Review fails closed when the stored envelope is invalid, and the state stays `submitted`. |
| Cancel | Cancel fails closed when the stored envelope is invalid. An unexpired `open` or `claimed` item stays in that state. A pre-envelope row can still be cancelled. |
| Expire | Effective expiry is unchanged. A bad envelope does not extend the deadline. `item_expired.occurred_at` is that item's `deadline_at`, including when claim, submit, or cancel is what observes the deadline. |
| Get | Until that actor's rejection cap, failure returns `envelope_rejected` and no item content. After the cap, failure returns `rate_limited`, still with no item content, and writes no audit row. A deliverable row follows the receipt rule below. |
| List | A failing row is a stub: `id`, effective `state`, `untrusted`, `owner_approval`, `envelope_status: "rejected"`. No title and no envelope. After the cap, that stub is unchanged and writes no audit row. Other rows on the page are returned. |

Claim and submit updates in [`src/item-lifecycle.ts`](../../src/item-lifecycle.ts) require the rebuilt digest. A null digest does not satisfy `= ?`, so the update changes no row. The handler reports `missing_envelope` or `digest_mismatch` from the stored columns, without returning item content.

Cancel and review fail closed when the stored envelope is invalid. These updates match no row, so the handler changes no state. The result omits title, body, result, sources, and envelope JSON. On cancel, `?4` is the digest of the canonical bytes just rebuilt. On review, that digest is `?7`. Malformed JSON, a flag other than `false`, or any other digest matches nothing. The handler returns `digest_mismatch` or `flag_not_false`. A null envelope is not this path. `claim_item`, `submit_result`, `review_result`, and `cancel_item` reject `scope` or `authority` in the input.

```sql
UPDATE item
SET state = 'cancelled', cancelled_at = ?3, updated_at = ?3
WHERE id = ?1 AND sender = ?2
  AND state IN ('open', 'claimed')
  AND deadline_at > ?3
  AND deadline_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  AND json_valid(envelope_json)
  AND (
    SELECT count(*) FROM json_each(envelope_json, '$.authority')
    WHERE key IN (
      'spending', 'credentials', 'credential_creation', 'private_resources',
      'external_actions', 'delegation', 'additional_tools',
      'message_grants_authority', 'resource_labels_grant_access')
      AND value = 0
  ) = 9
  AND envelope_sha256 = ?4;
UPDATE item
SET state = ?3, checked = ?4, review_note = ?5, reviewed_at = ?6, updated_at = ?6
WHERE id = ?1 AND sender = ?2
  AND state = 'submitted'
  AND json_valid(envelope_json)
  AND (
    SELECT count(*) FROM json_each(envelope_json, '$.authority')
    WHERE key IN (
      'spending', 'credentials', 'credential_creation', 'private_resources',
      'external_actions', 'delegation', 'additional_tools',
      'message_grants_authority', 'resource_labels_grant_access')
      AND value = 0
  ) = 9
  AND envelope_sha256 = ?7;
```

`execute: true` admits one attempt to answer the item. It is not owner approval and it turns no flag on. A successful get returns the canonical envelope and digest: the flags are server-rebuilt, and the scope lists are still sender-supplied data. Summaries carry the digest and omit the URLs. Logs may record `envelope.rejected` with the participant, the item id when one exists, and the fixed reason. They still omit item text, labels, envelope JSON, and URLs. The audit insert shares the lifecycle's primary D1 batch with the item change.

`open_item` gains a required `scope` and an optional `authority`, with `additionalProperties: false`. The owner refreshes the connector snapshot before public launch. No open path skips the envelope.

### Delivery receipts

Migration `0005_item_receipt.sql` adds `item.delivered_at`. Envelope validation binds recipient delivery receipts to the stored canonical envelope.

A row is deliverable when `envelope_json` and `envelope_sha256` are present, the stored digest equals the SHA-256 of the stored text, the rebuilt canonical bytes equal that text, and every flag is `false`. A legacy null envelope, malformed JSON, a digest mismatch, a flag other than `false`, and a list stub do not change `delivered_at`.

The first recipient read that stamps a deliverable row writes `item_delivered` in the same batch as the stamp. That read is `getItem`, or the inbox list including its `pending_items` sweep, whichever runs first. `#stampReceipts` updates every matching id in one statement. `changes()` there is the number of rows that statement updated, which is greater than 1 when the page and `pending_items` stamp more than one id. `getItem` stamps one id, so its `changes()` is 0 or 1. The invariant is per item, not per statement: each distinct id whose `delivered_at` this stamp changed from null gets one `item_delivered` row. The number of those inserts equals the number of rows the stamp changed. An id that appears on both the page and `pending_items` is one id. A stamp that changes no row for an id appends nothing. The insert is the same conditional shape as `item_expired`, keyed on that item and `item_delivered`, so a second insert for an item that already has the row is a no-op.

## Audit table

One row per committed lifecycle effect. An authenticated envelope rejection adds a row only while that actor is under the cap below:

| Column | Content |
| --- | --- |
| `seq` | `INTEGER PRIMARY KEY AUTOINCREMENT`, and `CHECK (seq >= 1)` |
| `event` | `item_opened`, `item_claimed`, `item_submitted`, `item_accepted`, `item_rejected`, `item_expired`, `item_cancelled`, `item_delivered`, `envelope_rejected` |
| `actor` | `grok_bot`, `dot`, `claude` (from migration 0007), or `system` (retention-job expiry only) |
| `item_id` | `item_` plus the UUID v4 from `crypto.randomUUID()`, or null when open fails before an id exists. The check is length 41, the `item_` prefix, hex and hyphens only, hyphens only at the UUID slots, version nibble `4`, and variant nibble `8`, `9`, `a`, or `b`. Each LIKE or GLOB pattern stays under D1's 50-byte limit |
| `envelope_sha256` | 64 lowercase hex digits, or null when a rejection has no well-formed digest. Required on `item_delivered`. |
| `reason` | Null on lifecycle events. Otherwise `unknown_key`, `wrong_type`, `duplicate`, `over_limit`, `non_canonical_url`, `bad_label`, `flag_not_false`, `digest_mismatch`, `citation_mismatch`, or `missing_envelope` |
| `occurred_at` | Server UTC from the same sample as the state change, except `item_expired`, which stores that item's `deadline_at`. The column accepts only the exact `strftime('%Y-%m-%dT%H:%M:%fZ')` form: length 24, `IS` that `strftime` of itself, and hour digits below `24`. A separate bound rejects a value before `2020-01-01T00:00:00.000Z` |

The row has no token, token hash, connect code, owner email, idempotency key, title, body, result, note, URL, label, or raw envelope. A failed audit insert rolls back the item change. A replay that changes no row appends nothing.

`item_opened`, `item_claimed`, `item_submitted`, `item_accepted`, `item_rejected`, and `item_cancelled` record one committed item change. `item_expired` is one fact per item, keyed by `(item_id, event)`, while that row is retained. Claim, submit, cancel, and the retention job can all observe the same deadline. That second observation is legitimate, so it must not abort the batch. Each of those writers uses this statement and omits `seq`. `?4` is the item's `deadline_at`. The caller is `?1` on claim, submit, and cancel. The retention job uses actor `system`. A valid envelope is not required.

```sql
INSERT INTO item_audit (event, actor, item_id, envelope_sha256, occurred_at)
SELECT 'item_expired', ?1, ?2, ?3, ?4
WHERE NOT EXISTS (
  SELECT 1 FROM item_audit
  WHERE event = 'item_expired' AND item_id = ?2
);
```

A second writer is a no-op. `WHERE NOT EXISTS` is false once that item has `item_expired`, the `SELECT` yields no row, and the `INSERT` adds nothing. `changes()` is 0. No `BEFORE INSERT` trigger runs, including `item_audit_one_expiry`, and the head does not move. The rest of the batch commits, including the cancel or the claim that observed the deadline. The expiry trigger still aborts a plain `INSERT` of a second row. None of the four writers issue that plain `INSERT`. `INSERT OR IGNORE` is not the dedupe, because it swallows every constraint failure. There is no `UNIQUE` index on the event: a `UNIQUE` index gives `REPLACE` a row to delete, and with `recursive_triggers` off (SQLite's default; D1's `PRAGMA` is per transaction) the `DELETE` trigger does not run for the delete inside `REPLACE INTO` or `INSERT OR REPLACE`. The partial index `item_audit_expiry` is the lookup. It is one covering-index search, not a `COUNT(*)` of the log. A retry after the batch commits finds the row and inserts nothing. A retry after the batch rolls back inserts once. After the row is pruned, the same statement inserts again, because the fact is no longer in the log.

`item_delivered` is the same kind of fact, keyed by `(item_id, event)`, and uses the same `INSERT ... WHERE NOT EXISTS` shape. The service omits `seq` on every insert.

Each actor may add at most 20 `envelope_rejected` rows per UTC day, the same order as the active-item cap. The admission check runs in the same primary batch as the insert, before it, and the insert is conditional on that count. The check reads at most 21 rows of `item_audit` for that actor and UTC day through the partial index `item_audit_rejection_cap`, then counts that small result. Lifecycle events do not count toward the cap. Once the actor is at 20, another validation failure returns `rate_limited` and writes no audit row and no counter. A pre-envelope claim or submit still returns `missing_envelope` after the cap. Its audit row is one conditional insert keyed on that item, `envelope_rejected`, and `missing_envelope`, so a retry adds nothing and does not switch the error to `rate_limited`. The admitted rows are the only aggregate. A rate-limit refusal must not be able to fill the log or block a later valid write.

`item_audit_no_replace` is the same `BEFORE INSERT` guard, adapted to an autoincrement key. `seq` is that table's only unique key. `BEFORE INSERT` runs before the delete inside `REPLACE`, and SQLite 3.45.1 presents an omitted `INTEGER PRIMARY KEY AUTOINCREMENT` as `-1` in that trigger (the same value seen for an explicit `NULL`). The guard aborts when `NEW.seq > 0`. A statement that names a live seq, a pruned seq, or any other explicit seq therefore fails and does not read `item_audit`. An ordinary insert leaves the guard false, so it does not probe the log. `CHECK (seq >= 1)` runs on the stored value, after autoincrement assignment, and rejects a stored seq of zero or below. The `-1` sentinel is not stored.

`item_audit_head` is one row (`id = 1`, `seq` starting at 0). The `AFTER INSERT` trigger on `item_audit` aborts when the assigned seq is less than or equal to that head, then sets the head to the new seq. The head's update trigger allows only a move to a greater seq that already exists in `item_audit`. Delete and replace of the head abort. A forward jump that does not land on an existing seq aborts, so it cannot stick and then reject the next insert. Nested triggers on the head fire even when `recursive_triggers` is off, because the head is a different table. The monotonic advance is the update that trigger allows.

Delete of an audit row is allowed only when `OLD.occurred_at` is strictly older than 90 days. The cutoff is `strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-90 days')`, compared as text with the `YYYY-MM-DDTHH:MM:SS.sssZ` form that `Date.toISOString()` stores on `deadline_at`. The trigger reads `OLD`. `NEW` has no columns in `BEFORE DELETE`. A newer row aborts. Deletes of audit rows older than 90 days are a separate batch and are not part of an item write. Items stay at 30 days.

`occurred_at` is stored only when `length(occurred_at) = 24`, `occurred_at IS strftime('%Y-%m-%dT%H:%M:%fZ', occurred_at)`, and `substr(occurred_at, 12, 2) < '24'`. That is the form `Date.toISOString()` writes and the form the cutoff uses. `IS` is 0 or 1. An invalid calendar value makes `strftime` return NULL. Comparing the column to that NULL with `=` makes the check NULL, and a NULL check passes, so the bad row would be stored. Hour 24 is not that NULL case. SQLite `strftime` keeps `2026-10-01T24:30:00.000Z` and `2026-10-28T24:00:00.000Z` as written, so `IS` is 1 and the bad row would be stored. The hour bound rejects those values. `2026-10-28T23:59:59.999Z` still passes. A value SQLite would rewrite, such as a date it normalizes or a timestamp with no fractional seconds, fails the check. A short string such as `0` or `2020-01-01` sorts before the cutoff and would be deleted before 90 days. The check rejects it, so it is not stored. A separate bound, `occurred_at >= '2020-01-01T00:00:00.000Z'`, rejects a well-formed timestamp that would still sort before the cutoff and be deleted at once. The comparison is text because the form is fixed.

```sql
DELETE FROM item_audit
WHERE occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-90 days');
DELETE FROM item
WHERE (state = 'expired' AND deadline_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-30 days'))
   OR (state IN ('submitted', 'accepted', 'rejected', 'cancelled') AND updated_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-30 days'));
```

The audit statement does not share a batch with open, claim, submit, get, list, or item retention. Item retention deletes from `item` only. A prune that also matches a fresh row aborts only the prune batch, so it cannot roll back a claim or an open. After a prune of old rows, the next omitted-seq insert still commits, and an insert of the deleted seq aborts. The prune does not update `sqlite_sequence` or `item_audit_head`.

On `item`, `REPLACE`, `INSERT OR REPLACE`, `INSERT ... ON CONFLICT DO REPLACE`, and `UPDATE OR REPLACE` delete every row that shares a unique key with the new row, then insert or apply the update. `BEFORE INSERT` and `BEFORE UPDATE` run before that delete. With `recursive_triggers` off, a `BEFORE DELETE` trigger does not run for the delete inside those statements, so a delete trigger is not the guard.

`item` has two declared unique keys, both in [`migrations/0002_item_lifecycle.sql`](../../migrations/0002_item_lifecycle.sql): the primary key `id`, and `UNIQUE (sender, idempotency_key)`. The envelope columns add none. The other indexes on `item` are not unique, so `REPLACE` cannot delete through them. `item_no_replace` aborts an insert when `id` already exists, or when `(sender, idempotency_key)` is already owned by any id. That key check does not compare ids, so a fresh id is not a miss. `item_no_replace_update` aborts an update of `id`, `sender`, or `idempotency_key` when the new value is owned by a different row. A later `UNIQUE` constraint on `item` is added to both `WHEN` clauses in the migration that creates the constraint. A constraint left out of those clauses is a row `REPLACE` can still delete.

The text primary key leaves SQLite's implicit integer `rowid` in place. `oid` and `_rowid_` are that same key, and `REPLACE` deletes whichever row already holds the supplied value. A `BEFORE INSERT` guard cannot close that hole. On SQLite 3.45.1 an omitted `rowid` is `-1` inside `BEFORE INSERT`, and `-1`, `0`, and other negative values are legal stored rowids. The guard cannot tell an ordinary insert from an explicit `rowid` of `-1`. After any row stores `-1`, the same predicate rejects every later ordinary insert. `BEFORE UPDATE OF rowid` also misses `SET oid` and `SET _rowid_`. The sketch therefore rebuilds `item` as `WITHOUT ROWID`. `rowid`, `oid`, and `_rowid_` are not columns, so `INSERT OR REPLACE` and `UPDATE OR REPLACE` that name them fail before any row is deleted. An `INTEGER PRIMARY KEY` is not a fit: `id` stays text, and a new integer primary key would still be a `rowid` a statement can target. SQLite cannot add `WITHOUT ROWID` with `ALTER TABLE`, so the rebuild copies the existing rows, including `delivered_at` from migration 0005, and recreates the four indexes. The envelope columns stay null.

An insert of a new `id` and a new `(sender, idempotency_key)` commits. The insert `WHEN` is false. Each `EXISTS` is a lookup on that unique key, not a scan of `item`.

An `INSERT`, `REPLACE`, `INSERT OR REPLACE`, or `INSERT ... ON CONFLICT DO REPLACE` that matches an existing `id`, or that uses a fresh `id` with a `(sender, idempotency_key)` owned by any existing id, aborts with `item_envelope_immutable`. The existing rows stay, with their ids, state, and envelope columns. On SQLite 3.45.1 an id-only guard misses the fresh-id case: the statement commits and the original row is gone.

`UPDATE OR REPLACE item SET idempotency_key = 'existing-key' WHERE id = 'other-id'` deletes the row that already owns that sender and key, then moves the key onto the other envelope. The insert guard does not run. `item_envelope_immutable` does not run, because the statement assigns neither envelope column. `item_no_replace_update` aborts while both rows are still present, so the conflict-resolution delete does not run. The owner keeps the key. The other row keeps its own key, state, and envelope. The same abort applies when `UPDATE OR REPLACE` sets `sender` or `id` to a value another row owns. `INSERT OR REPLACE` and `UPDATE OR REPLACE` that name `rowid`, `oid`, or `_rowid_` fail with no such column, and both rows stay. A lifecycle update that assigns none of those columns commits. An update of those columns that does not collide with another row commits, and it deletes nothing. `BEFORE UPDATE` runs before `ON CONFLICT` resolution, so `UPDATE OR IGNORE` of a colliding `id`, `sender`, or `idempotency_key` also aborts. It is not a no-op.

`BEFORE INSERT` runs before `ON CONFLICT` resolution, so `ON CONFLICT(sender, idempotency_key) DO NOTHING`, `DO UPDATE`, and `INSERT OR IGNORE` also abort when that key exists. `changes()` is not 0. Those clauses are not a replay. Open does not insert a live key. It reads `(sender, idempotency_key)` and returns that row, as `openItem` already does before the insert at `src/item-lifecycle.ts:183`. The insert at `src/item-lifecycle.ts:200` uses `ON CONFLICT(sender, idempotency_key) DO NOTHING` for the race where two opens both pass that read. That clause aborts once this guard exists. The losing statement stops, the first row remains, and the loser reads the key again and returns that row. It does not insert again. An insert the cap predicate skips still changes no row and does not run the trigger. The service does not issue `REPLACE`, `INSERT OR REPLACE`, `UPDATE OR REPLACE`, or `ON CONFLICT DO REPLACE` against `item`. The triggers are what stop them if they are issued.

`item_audit` has one unique key, `seq`. `item_audit_no_replace` aborts when `NEW.seq > 0`, which is every explicit seq those statements can use to delete a row. The partial indexes are not unique, so they do not give `REPLACE` a row to delete. `item_audit_head` has one unique key, `id`, and `item_audit_head_no_replace` matches it.

An update of either envelope column aborts. State updates and retention deletes of items stay allowed. Later lifecycle updates must not assign the envelope columns. The audit tables do not reference `item`. The account owner can drop a trigger. Short of that, ordinary SQL cannot rewrite a retained audit row, and it cannot replace an item row through `id` or `(sender, idempotency_key)`. `item` has no `rowid` column after the rebuild. `item_audit.seq` and `item_audit_head.id` are `INTEGER PRIMARY KEY`, so their `rowid` is that declared column and the guards on those columns already cover it.

Cost of one ordinary audit write: one insert that omits `seq`, one read of the single head row, one primary-key lookup of the new seq inside the head update, and one update of that head row. No `COUNT(*)` of `item_audit`. The replace guard does not read the log. An `item_expired` or `item_delivered` writer adds one covering-index lookup in `WHERE NOT EXISTS`. A miss inserts the row. A hit inserts nothing, does not run the event trigger, and does not move the head. The rejection cap is not on this path. It reads at most 21 index entries, and only for an envelope rejection.

### Hash chain

Basic does not add a hash chain. The `item_audit` triggers protect retained rows from update and replacement, with separate retention deletes; they do not make credential revocation append-only. A future chain would need an independent external checkpoint before it could provide tamper evidence against a database owner able to rebuild the tables.

## Migration

Migration [`0006_authority_envelope.sql`](../../migrations/0006_authority_envelope.sql) follows migration 0005, which adds `delivered_at`. Existing migrations must never be reused or renumbered. The SQL below is a design sketch; use the checked-in migration files for an authorized installation:

```sql
CREATE TABLE item_authority (
  id TEXT NOT NULL PRIMARY KEY,
  sender TEXT NOT NULL CHECK (sender IN ('grok_bot', 'dot')),
  recipient TEXT NOT NULL CHECK (recipient IN ('grok_bot', 'dot')),
  kind TEXT NOT NULL CHECK (kind IN ('task', 'question', 'proposal')),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open', 'claimed', 'submitted', 'accepted', 'rejected', 'expired', 'cancelled')),
  deadline_at TEXT NOT NULL,
  result TEXT,
  sources TEXT,
  review_note TEXT,
  checked INTEGER CHECK (checked IN (0, 1)),
  idempotency_key TEXT NOT NULL,
  request_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  claimed_at TEXT,
  submitted_at TEXT,
  reviewed_at TEXT,
  cancelled_at TEXT,
  updated_at TEXT NOT NULL,
  delivered_at TEXT,
  envelope_json TEXT,
  envelope_sha256 TEXT
    CHECK (envelope_sha256 IS NULL OR (
      length(envelope_sha256) = 64 AND envelope_sha256 NOT GLOB '*[^0-9a-f]*')),
  CHECK (sender <> recipient),
  UNIQUE (sender, idempotency_key)
) WITHOUT ROWID;
INSERT INTO item_authority (
  id, sender, recipient, kind, title, body, state, deadline_at, result, sources,
  review_note, checked, idempotency_key, request_sha256, created_at, claimed_at,
  submitted_at, reviewed_at, cancelled_at, updated_at, delivered_at)
SELECT
  id, sender, recipient, kind, title, body, state, deadline_at, result, sources,
  review_note, checked, idempotency_key, request_sha256, created_at, claimed_at,
  submitted_at, reviewed_at, cancelled_at, updated_at, delivered_at
FROM item;
DROP TABLE item;
ALTER TABLE item_authority RENAME TO item;
CREATE INDEX item_recipient_created ON item (recipient, created_at, id);
CREATE INDEX item_sender_created ON item (sender, created_at, id);
CREATE INDEX item_recipient_state ON item (recipient, state, created_at, id);
CREATE INDEX item_sender_state ON item (sender, state, created_at, id);

CREATE TRIGGER item_envelope_immutable
BEFORE UPDATE OF envelope_json, envelope_sha256 ON item
BEGIN SELECT RAISE(ABORT, 'item_envelope_immutable'); END;
CREATE TRIGGER item_no_replace
BEFORE INSERT ON item
WHEN EXISTS (
    SELECT 1 FROM item AS existing
    WHERE existing.sender = NEW.sender
      AND existing.idempotency_key = NEW.idempotency_key)
  OR EXISTS (SELECT 1 FROM item AS existing WHERE existing.id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'item_envelope_immutable'); END;
CREATE TRIGGER item_no_replace_update
BEFORE UPDATE OF id, sender, idempotency_key ON item
WHEN EXISTS (
    SELECT 1 FROM item AS existing
    WHERE existing.id = NEW.id AND existing.id != OLD.id)
  OR EXISTS (
    SELECT 1 FROM item AS existing
    WHERE existing.sender = NEW.sender
      AND existing.idempotency_key = NEW.idempotency_key
      AND existing.id != OLD.id)
BEGIN SELECT RAISE(ABORT, 'item_envelope_immutable'); END;

CREATE TABLE item_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT CHECK (seq >= 1),
  event TEXT NOT NULL CHECK (event IN (
    'item_opened','item_claimed','item_submitted','item_accepted',
    'item_rejected','item_expired','item_cancelled','item_delivered',
    'envelope_rejected')),
  actor TEXT NOT NULL CHECK (actor IN ('grok_bot','dot','system')),
  item_id TEXT CHECK (item_id IS NULL OR (
    length(item_id) = 41
    AND substr(item_id, 1, 5) = 'item_'
    AND substr(item_id, 6) NOT GLOB '*[^0-9a-f-]*'
    AND substr(item_id, 14, 1) = '-'
    AND substr(item_id, 19, 1) = '-'
    AND substr(item_id, 24, 1) = '-'
    AND substr(item_id, 29, 1) = '-'
    AND substr(item_id, 20, 1) = '4'
    AND substr(item_id, 25, 1) IN ('8', '9', 'a', 'b')
    AND length(replace(substr(item_id, 6), '-', '')) = 32)),
  envelope_sha256 TEXT CHECK (envelope_sha256 IS NULL OR (
    length(envelope_sha256) = 64 AND envelope_sha256 NOT GLOB '*[^0-9a-f]*')),
  reason TEXT CHECK (reason IS NULL OR reason IN (
    'unknown_key','wrong_type','duplicate','over_limit','non_canonical_url',
    'bad_label','flag_not_false','digest_mismatch','citation_mismatch',
    'missing_envelope')),
  occurred_at TEXT NOT NULL
    CHECK (length(occurred_at) = 24
      AND occurred_at IS strftime('%Y-%m-%dT%H:%M:%fZ', occurred_at)
      AND substr(occurred_at, 12, 2) < '24'
      AND occurred_at >= '2020-01-01T00:00:00.000Z'),
  CHECK (actor != 'system' OR event = 'item_expired'),
  CHECK (event = 'envelope_rejected' OR item_id IS NOT NULL),
  CHECK ((event = 'envelope_rejected') = (reason IS NOT NULL)),
  CHECK (event != 'item_delivered' OR envelope_sha256 IS NOT NULL)
);
CREATE INDEX item_audit_expiry
  ON item_audit (item_id) WHERE event = 'item_expired';
CREATE INDEX item_audit_delivery
  ON item_audit (item_id) WHERE event = 'item_delivered';
CREATE INDEX item_audit_rejection_cap
  ON item_audit (actor, occurred_at) WHERE event = 'envelope_rejected';

CREATE TABLE item_audit_head (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  seq INTEGER NOT NULL CHECK (seq >= 0)
);
CREATE TRIGGER item_audit_head_no_replace
BEFORE INSERT ON item_audit_head
WHEN EXISTS (SELECT 1 FROM item_audit_head AS existing WHERE existing.id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_head_block_update
BEFORE UPDATE ON item_audit_head
WHEN NEW.seq <= OLD.seq
  OR NOT EXISTS (SELECT 1 FROM item_audit WHERE seq = NEW.seq)
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_head_block_delete
BEFORE DELETE ON item_audit_head
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
INSERT INTO item_audit_head (id, seq) VALUES (1, 0);

CREATE TRIGGER item_audit_no_replace
BEFORE INSERT ON item_audit
WHEN NEW.seq > 0
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_one_expiry
BEFORE INSERT ON item_audit
WHEN NEW.event = 'item_expired' AND EXISTS (
  SELECT 1 FROM item_audit
  WHERE event = 'item_expired' AND item_id = NEW.item_id)
BEGIN SELECT RAISE(ABORT, 'item_audit_one_expiry'); END;
CREATE TRIGGER item_audit_one_delivery
BEFORE INSERT ON item_audit
WHEN NEW.event = 'item_delivered' AND EXISTS (
  SELECT 1 FROM item_audit
  WHERE event = 'item_delivered' AND item_id = NEW.item_id)
BEGIN SELECT RAISE(ABORT, 'item_audit_one_delivery'); END;
CREATE TRIGGER item_audit_block_update
BEFORE UPDATE ON item_audit
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_block_delete
BEFORE DELETE ON item_audit
WHEN OLD.occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-90 days')
BEGIN SELECT RAISE(ABORT, 'item_audit_append_only'); END;
CREATE TRIGGER item_audit_head_advance
AFTER INSERT ON item_audit
BEGIN
  SELECT RAISE(ABORT, 'item_audit_append_only')
    WHERE NEW.seq <= (SELECT seq FROM item_audit_head WHERE id = 1);
  UPDATE item_audit_head SET seq = NEW.seq WHERE id = 1 AND seq < NEW.seq;
END;
```

The rebuild copies every existing column and leaves `envelope_json` and `envelope_sha256` null. Null is not an empty allow-list, and the migration backfills no envelope. The copy is there because `WITHOUT ROWID` cannot be added with `ALTER TABLE`. Claim and submit of a pre-envelope item return `missing_envelope` on every attempt, including after the rejection cap. They do not return `rate_limited`. Cancel of a pre-envelope row still works. Cancel and review of an invalid stored envelope do not. New opens write both columns. The migration does not touch `owner_lock`, `bootstrap_secret_spend`, `participant`, `participant_credential`, or `connect_code`. CI does not apply the file. An operator applies it only after the owner approves the implementation.

The apply must stop on the first error. D1 does this. With the sqlite3 CLI, use `-bail`:

```sh
sqlite3 -bail database.sqlite < migrations/0006_authority_envelope.sql
```

The sqlite3 CLI otherwise continues after an error. The first statement is a guard that aborts when `item_audit` or `item.envelope_json` already exists, before the rebuild copies or drops a row. Continuing past that error rebuilds `item` and stores null envelopes. Pre-0006 rows keep a null envelope on the first apply by design. A second apply must not clear an envelope that is already set.

The implementation must prove the pinned bytes and digest, the rejection cases, idempotency, claim and submit refusal when the rebuilt digest does not match (`missing_envelope` and `digest_mismatch` change no state and are not `wrong_state`), citation subset, silent logs, cancel of a pre-envelope row, and the 20-row rejection cap (the next validation failure returns `rate_limited`, writes nothing, and a later valid open still commits). A pre-envelope claim or submit still returns `missing_envelope` after that cap. It must prove a duplicate key is rejected before `JSON.parse`, including two spellings that decode to one key, that a legacy, malformed, or mismatched row and a list stub do not set `delivered_at` or append `item_delivered`, and that a stamp which changes N deliverable rows appends N `item_delivered` rows. It must prove `item_expired.occurred_at` equals that item's `deadline_at`, and that a second `item_expired` writer for that item inserts no row, leaves `changes()` at 0, and commits the rest of the batch. It must prove `UPDATE`, `DELETE` of a row newer than 90 days, `REPLACE INTO`, and `INSERT OR REPLACE` abort on the audit tables; that a delete of a row older than 90 days commits and the next omitted-seq insert still commits; that an ordinary audit write does not run `COUNT(*)` over `item_audit`; and that item state updates and item deletes still work. It must prove that on `item`, `REPLACE`, `INSERT OR REPLACE`, and `INSERT ... ON CONFLICT DO REPLACE` abort when the new row reuses an existing `id` or a `(sender, idempotency_key)` owned by any id, including a fresh id with a live idempotency key, and that the original row remains. It must prove `UPDATE OR REPLACE` of `idempotency_key`, `sender`, or `id` onto a value owned by another row aborts and leaves both rows in place, and that a lifecycle state update still commits. It must prove `INSERT OR REPLACE` and `UPDATE OR REPLACE` that name `rowid`, `oid`, or `_rowid_` fail because those are not columns, and that both original rows stay. It must prove an insert of a new id and a new idempotency key commits, and that `ON CONFLICT(sender, idempotency_key) DO NOTHING` and `INSERT OR IGNORE` abort when the key exists. It must prove cancel and review of an invalid stored envelope change no state, and that item retention deletes a finished row 30 days after its last change while an audit row of that age remains. Tests use the local SQLite stand-in. They apply nothing to a live database. The `allowed_sources` sketch must prove the stored canonical list, rejection of a hostname the URL parser would rewrite, the empty list admitting no citation, and that building the envelope performs no fetch and leaves every flag `false`. It does not prove the receiver's egress checks. The Bridge does not implement those checks.

## Out of scope

- Provider internals. The bridge governs its boundary, not the provider's steps. `max_steps` stays advisory.
- Multi-tenant and multi-owner installs.
- Participants beyond `grok_bot`, `dot`, and `claude`, including Antigravity, and any engineering execution lane. The SQL sketch records migration 0006; migration 0007 extends its participant checks without changing this envelope contract.
- The Worker fetching a URL. Listing an `allowed_source` constrains permitted citations. It does not grant a read. A receiver may read it only under independently established read permissions. The Bridge does not run the receiver's egress checks. Recording an owner approval, or storing a `true` flag, is out of scope.
- Cloudflare configuration, bindings, secrets, and deployment.

## Contract decisions

1. A denial record is enough for v1; there is no owner flag-set path.
2. Cancel and review fail closed when the stored envelope is invalid.
3. Audit retention is 90 days; item retention is 30 days.
4. `external_actions` stays a single flag.
5. A corrupt envelope returns a list stub.
6. Listing a URL constrains permitted citations; it does not grant network, credential, private-resource or external-action authority. A receiver may read it only under independently established read permissions and applicable safety checks, including redirects. All-false flags grant no additional authority.
