# Owner email lock

**Owner-lock design, now implemented.** The Worker serves `POST /owner/claim` (`src/owner-claim.ts`), and `migrations/0001_owner_lock.sql` creates its tables.

The MVP path is Grok Bot ↔ Dot (ChatGPT). This document does not specify any other participant.

## Decision

The operator sets `OWNER_EMAIL` in their private Wrangler config. That var stays a var. It is personal data and is never logged.

The operator also sets a one-time bootstrap secret with `wrangler secret put`. The secret is not in the Wrangler file. The claim must present that secret. The Worker compares it in constant time. The first successful claim writes the owner email, as entered, into one D1 row and spends the secret. A spent secret cannot lock an owner again.

Before that secret is set, and before the claim is sent, the owner confirms the exact `OWNER_EMAIL` from the private config, that config is deployed, and the deployed var is read back and matched. See Confirm the owner email.

There is no unauthenticated claim. A request that does not present the bootstrap secret writes nothing. The body is not a credential.

The lock records who the owner is. It does not authenticate Grok Bot, Dot, or later bridge traffic. Mailbox proof is not part of the MVP. The operator's authority is ownership of the Cloudflare account. Mailbox proof is a future option.

## Configuration

The foundation template carries this non-secret var:

```jsonc
"vars": {
  "OWNER_EMAIL": "<OWNER_EMAIL>"
}
```

The operator replaces `<OWNER_EMAIL>` in their gitignored `wrangler.jsonc`. The tracked template keeps the placeholder.

`OWNER_EMAIL` is personal data. The Worker must not write it to logs, traces, responses, or error text. The private Wrangler file is the only copy in config, and that file stays gitignored.

## Confirm the owner email

Before `BOOTSTRAP_SECRET` is set, and before `POST /owner/claim` is sent, the operator or the installing bot reads `OWNER_EMAIL` from the private Wrangler config and shows the owner that exact string, in full, in the owner's own chat. The read-back is not logged.

The owner must explicitly confirm that string. If the owner does not confirm it, or the confirmation does not match it, stop. Do not deploy. Do not put the secret. Do not send the claim.

`wrangler secret put` changes the Worker that is already deployed and keeps the vars on that deployment. Confirming only the local file can leave a stale `OWNER_EMAIL` on the Worker, and the claim stores the deployed value. After the owner confirms the private-config string, deploy that config:

```sh
wrangler deploy --config wrangler.jsonc
```

Do not put `BOOTSTRAP_SECRET` in this deploy.

Then read `OWNER_EMAIL` from the deployed Worker's configuration: the `plain_text` binding on the Worker script settings (`GET /accounts/{account_id}/workers/scripts/{script_name}/settings`). That read is the control plane. It is not a Worker response, and it is not logged.

If that deployed string is not the exact string the owner confirmed, stop. Do not put the secret. Do not send the claim.

Only then set the secret, and only then send the claim. No other deploy comes between the matching read and `wrangler secret put`.

The confirmation changes nothing in the Worker and needs no route. No response includes the email.

Mailbox verification, sending mail to prove ownership of the address, stays after the MVP.

Claude's other four review points are already covered by this design: concurrent claims, a missing secret fails closed, secret redaction, and the authentication check before any `409`. Concurrent claims are settled in Race on first boot. A missing secret fails closed as `bootstrap_not_configured` and writes nothing. Logging omits the secret. The constant-time compare runs before any `409`.

The bootstrap secret is a Worker secret named `BOOTSTRAP_SECRET`, read at runtime as `env.BOOTSTRAP_SECRET`. Set it only after the deployed `OWNER_EMAIL` matches the string the owner confirmed, with Wrangler:

```sh
wrangler secret put BOOTSTRAP_SECRET --config wrangler.jsonc
```

Wrangler reads the value from a hidden prompt, or from stdin when there is no terminal. It trims trailing whitespace. Do not pass the value as a command-line argument, and do not put it in `wrangler.jsonc`, `.dev.vars`, chat, or logs. `wrangler secret put` and `wrangler secret delete` upload the secret change onto the Worker. Treat both as a deploy. This repository's CI does not run them.

Every bootstrap secret, including one set by hand for a reset, is 32 bytes from `crypto.getRandomValues`, encoded as base64url without padding. That encoding is 43 characters from `A-Za-z0-9_-`. It has no comma, no `=` padding, and no whitespace. A passphrase is not a bootstrap secret.

The D1 binding name is `DB`. The KV binding in the template is not part of this design.

Rules for the configured email:

- Read `env.OWNER_EMAIL` at claim time.
- Store that string as entered. Do not trim it, lowercase it, or otherwise rewrite it in the row.
- Compare with the key `trim`, then `toLowerCase`. ` Ada@Example.com ` and `ada@example.com` are the same owner. The stored characters stay as entered.
- Reject the value when the comparison key is empty.
- Reject the value when the comparison key equals the comparison key of `<OWNER_EMAIL>`.
- A rejected value writes nothing.

`GET /health` does not read the var, the secret, or D1, and it does not write.

## Grok Bot template

The public template is not part of Phase 0. `templates/grok-bot/` stays a placeholder README until the MVP works end to end. When a later template or bot drives the deploy, it confirms the owner email, deploys that config, and only then handles the bootstrap secret as follows:

1. Follow Confirm the owner email. Read the exact `OWNER_EMAIL` from the private config, show that full string in the owner's own chat, and wait for an explicit confirmation. Do not log it. If the owner does not confirm it, or the confirmation does not match it, stop. Do not deploy, do not set the secret, and do not send the claim.
2. Deploy that private config with `wrangler deploy --config wrangler.jsonc`. Do not put `BOOTSTRAP_SECRET` in this deploy.
3. Read `OWNER_EMAIL` from the deployed Worker's script settings, as in Confirm the owner email. Do not log it, and do not read it from a Worker response. If it is not the exact string the owner confirmed, stop. Do not put the secret and do not send the claim.
4. Generate 32 bytes with `crypto.getRandomValues` and encode them as base64url without padding. The result is 43 characters from `A-Za-z0-9_-`. Do not use `Math.random`. The value has no comma, no padding, and no whitespace.
5. Set it by piping that value to `wrangler secret put BOOTSTRAP_SECRET` on stdin, using the operator's private Wrangler config. The value is not a command-line argument. This follows the matching deploy, with no other deploy between them.
6. Keep the value in process memory only. Do not show it in chat, print it, write it to a log, or store it in the repo.
7. Send the claim from that same process. The `Bootstrap-Secret` header carries the value. The chat transcript does not.
8. Follow Secret lifetime below. If no claim will be sent, do not leave the secret deployed, and do not ask the operator to copy it into chat.

The template may ask the operator for the email address that goes in the `OWNER_EMAIL` var. It must not log that address. Asking for the address is not the confirmation. The confirmation reads back the value already in the private config.

## Claim

The Worker has one write route: `POST /owner/claim`.

The bootstrap secret is presented only in the `Bootstrap-Secret` request header. A secret in the query string, the path, or the body is ignored and is not a credential. Workers return that header from `Headers.get` as one string. Repeated fields are concatenated into one comma-delimited string, and `Headers.getAll` throws for every name except `Set-Cookie`, so the Worker cannot count header fields. See [Headers](https://developers.cloudflare.com/workers/runtime-apis/headers/).

Read that one string. A missing header, an empty string, or any value other than 43 characters from `A-Za-z0-9_-` is `401` with `{ "error": "bootstrap_secret_required" }`. A comma, a space, or a comma-joined repeat fails that check. Write nothing, and do not compare the value to `env.BOOTSTRAP_SECRET`.

A non-empty body, including a body that contains an email, is `400` with `{ "error": "claim_body_not_allowed" }`. Write nothing. The caller cannot choose the owner address.

When the header matches the 43-character rule, apply these rules in order:

1. If `OWNER_EMAIL` is missing or rejected by the rules above, respond `422` with `{ "error": "owner_not_configured" }`. Write nothing.
2. If `BOOTSTRAP_SECRET` is missing, empty, or not 43 characters from `A-Za-z0-9_-`, respond `422` with `{ "error": "bootstrap_not_configured" }`. Write nothing. Do not compare.
3. Compare the header value to `env.BOOTSTRAP_SECRET` in constant time, as specified below. If they differ, respond `401` with `{ "error": "bootstrap_rejected" }`. Write nothing.
4. If the SHA-256 of the secret is already in `bootstrap_secret_spend`, the secret is spent. Respond `409` with `{ "error": "bootstrap_spent" }`. Write nothing.
5. If the owner row exists and the comparison key of the configured email differs from the comparison key of the stored email, respond `409` with `{ "error": "owner_mismatch" }`. Do not update the row and do not spend this secret.
6. If the owner row exists and the comparison keys match, respond `409` with `{ "error": "owner_locked" }`. Do not update `claimed_at` and do not spend a secret that is not already spent.
7. If the owner row is absent, insert the owner row and the spend row together. On success, respond `201` with `{ "locked": true }`.

No response, log line, or error text includes the email or the secret.

The successful write is one D1 batch. `?1` is `OWNER_EMAIL` as entered. `?2` is UTC time from `new Date().toISOString()`, an audit field, not an authorization input. `?3` is the hex SHA-256 of the secret.

```sql
INSERT INTO owner_lock (id, owner_email, claimed_at, claim_source)
VALUES (1, ?1, ?2, 'first-boot');

INSERT INTO bootstrap_secret_spend (secret_sha256, spent_at)
VALUES (?3, ?2);
```

`claim_source` is the constant `first-boot`. Bound parameters only.

## Constant-time secret compare

Hash both UTF-8 values with SHA-256, then compare the digests with `crypto.subtle.timingSafeEqual`. Do not use `===` on the secret. Do not return early when the lengths differ. Run this compare only after both the header and `env.BOOTSTRAP_SECRET` have matched the 43-character base64url rule, and before any spend or owner write.

That API is the Workers extension documented at [Web Crypto `timingSafeEqual`](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/#timingsafeequal).

The email comparison key is `trim` then `toLowerCase`. It is not the secret compare. The email is never taken from the request.

## Race on first boot

Two isolates can both see an empty owner table, both match the same secret, and both attempt the batch. The owner primary key and the spend primary key allow one batch to commit. D1 rolls the other batch back.

A constraint failure is not success and is not a reason to try a different email or a different secret. The loser re-reads both tables from the primary. If the spend row for that hash exists, the result is `bootstrap_spent`. If the owner row exists and the spend row does not, the result follows the mismatch or `owner_locked` rule. If neither row exists, the claim fails closed and does not insert again.

D1 `batch()` runs its statements as one transaction. Batching a `SELECT` with an `INSERT` does not, by itself, stop two Workers from both seeing an empty table. The primary keys are the race control.

Owner-lock reads and writes use a primary D1 session (`withSession("first-primary")`). Leave read replication off for this database until a later design revisits it.

The lock and the spent secret are not held in module memory, KV, or a global variable.

## Takeover

A caller who does not have the bootstrap secret cannot create the owner row. `GET /health` is not a claim and cannot spend the secret or freeze the email.

A caller who steals the secret before the first successful claim can lock the configured email once. They still cannot submit a different email. After that claim, the secret is spent. Presenting it again does not change the row and does not lock a new owner.

The Grok Bot path keeps the secret out of chat and logs so the transcript is not a copy of the credential. It follows Secret lifetime, so the Worker secret is removed after every claim attempt. A spend row still rejects that value if it is uploaded again.

Someone who can change the deployed var or secret already controls the Cloudflare account. After the owner row exists, changing `OWNER_EMAIL` does not rewrite the row. A difference under the comparison key fails closed. Changing the Worker secret does not spend the new value and does not replace the owner while the row exists.

A second deployment with a different D1 database is a different lock. This design is single-tenant.

## Rate limiting

`POST /owner/claim` has no request rate limit. The lock does not depend on one:

- The secret is 32 random bytes. Guessing it is infeasible at any request rate.
- The secret is on the Worker only for the claim about to be sent. See Secret lifetime. At any other time a well-formed guess is rejected before the compare, with `bootstrap_not_configured` or an earlier error.
- The header check and rules 1 to 3 use no storage. A request that does not present the secret never reads or writes D1.
- A successful claim spends the secret, so holding it allows one claim.

A limit inside the Worker would not cut request volume. The Worker has already run, and the request already counts against the account, before the handler could refuse it. Volume limits belong in front of the Worker, for example a rate-limiting rule on the operator's own zone. That rule is the operator's choice and is not part of Basic.

## Secret lifetime

`BOOTSTRAP_SECRET` is on the Worker only for the claim that is about to be sent.

Delete it with `wrangler secret delete BOOTSTRAP_SECRET --config wrangler.jsonc`. Then `wrangler secret list --config wrangler.jsonc` must not include that name. The list prints names, not values. Do this before any restore, retry, re-claim, or `DELETE` of `owner_lock`.

That delete deploys a new version immediately. The list is only the control plane. A deployment can take a couple of seconds to be available globally, and a request already running keeps the secret and `OWNER_EMAIL` it started with. See [Secrets](https://developers.cloudflare.com/workers/configuration/secrets/#delete-secrets-from-your-project) and [version availability](https://developers.cloudflare.com/workers/versions-and-deployments/version-overrides/#verify-that-version-overrides-were-applied). Before either D1 change, the owner `DELETE` or a Time Travel restore, remove the route so `POST /owner/claim` receives nothing new, and wait until those in-flight claims have finished. Do not change D1 on the strength of the secret list alone.

Every claim attempt, with any outcome (`201`, any other status, a timeout, or no response), is followed by that same delete and a primary re-read of both tables. Do not log the email or the secret. If the spend row for the value just used exists, stop and do not upload it again. Upload a new secret only when `owner_lock` is absent, the secret name is absent, and no earlier version is still serving the claim, and only after Confirm the owner email.

## Reset

There is no request path that updates or deletes either table. Rotation, a lost claim, and Time Travel are operator actions on their own Cloudflare account, and they follow Secret lifetime. An unspent secret left on the Worker becomes a valid claim as soon as `owner_lock` is gone. The `owner_locked` rule does not spend a secret while that row exists, so a spend row is not what closes the window.

1. Deploy the corrected `OWNER_EMAIL`. Do not claim while the old row remains.
2. Follow Secret lifetime: the secret name is absent, the claim route is off, and in-flight claims have finished. Then delete only the owner row:

```sh
wrangler d1 execute DB --remote --config wrangler.jsonc --command "DELETE FROM owner_lock WHERE id = 1;"
```

`DB` is the D1 binding. `--command` runs after Wrangler authenticates. Read the statement before you run it. Do not delete `bootstrap_secret_spend`. A Time Travel restore can still rewind those rows. The Worker does not call it.

3. No claim is served in the gap. A hash already in `bootstrap_secret_spend` cannot be used again. When `owner_lock` is absent and the route is back, follow Confirm the owner email, then generate a new 43-character secret, claim once, and follow Secret lifetime.

A [D1 restore overwrites the whole database in place](https://developers.cloudflare.com/d1/reference/time-travel/#restore-a-database). It restores both tables. It does not keep spend rows written after the restore point, and it does not change the Worker secret. Follow Secret lifetime before `wrangler d1 time-travel restore`, so the route is off and no in-flight claim still holds a secret. After the restore, keep the route off, re-read both tables, and keep the spend rows the restore brought back. If that owner row is the one to keep, put the route back with no secret deployed and stop. If not, delete only `owner_lock` while no claim is being served, then put the route back, follow Confirm the owner email, generate, claim once, and follow Secret lifetime.

Losing access to the Cloudflare account is not recoverable from inside the Worker.

## Storage

`migrations/0001_owner_lock.sql` creates these tables. Apply it before the first claim.

```sql
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
```

`owner_email` is the address as entered. `bootstrap_secret_spend` stores the hex SHA-256 of a secret that has already locked an owner. It does not store the secret.

No tokens, receipts, source addresses, or request logs. The KV namespace is not a copy of either table.

The D1 binding can run any SQL the Worker sends. Claim handling may prepare only the reads of these two tables and the two `INSERT` statements in this document. `UPDATE` and `DELETE` belong to the operator command above, not to a fetch handler. The operator delete names `owner_lock` only.

## Logging

Log the claim outcome as structured JSON: message, HTTP status, and the error code. Do not log `OWNER_EMAIL`, the stored email, `BOOTSTRAP_SECRET`, the `Bootstrap-Secret` header, the request body, the request URL, or the query string.

The foundation template sets `observability.redact_query_string` to true. Keep that on for any deployment that serves the claim. The secret is still not accepted from the query string.

The template also sets `observability.logs.invocation_logs` to false. Workers Logs invocation logs capture request headers, and `Bootstrap-Secret` is a request header. Cloudflare documents header redaction for Tail Workers, not for Workers Logs. Keep invocation logs off for any deployment that serves the claim. The Worker's own log lines name the route, not the path. Traces still record request URLs, so the secret never goes in a URL.

## Out of scope

- Authenticating Grok Bot, Dot, or Claude, and any session, token, webhook, or OAuth design for bridge traffic. Participant authentication is specified separately in the [Claude Basic design](claude-basic-participant.md).
- Mailbox proof. A later design may require the operator to prove control of the mailbox. The MVP does not. The chat read-back in Confirm the owner email is not that proof.
- More than one owner, delegates, or an organization.
- Changing the locked email through the Worker.
- A hosted multi-tenant service.
- Participants beyond Grok Bot, Dot (ChatGPT), and Claude. Antigravity stays out of Basic.
- Using this row as the authorization check for bridge messages.
- D1 read replication, a backup schedule, and recovery from losing the Cloudflare account. An operator restore with D1 Time Travel follows the Reset rules above.
- The public Grok Bot template itself. The behavior above applies when that template exists. Phase 0 only reserves its directory.

## Tests the implementation owes

The implementation stays behind tests and ships no secrets. `test/owner-claim.test.ts` and `test/health.test.ts` show at least:

- A missing or empty `Bootstrap-Secret` header writes nothing and returns `bootstrap_secret_required`.
- A header value that is not 43 characters from `A-Za-z0-9_-`, including a comma or a comma-joined repeated header, writes nothing, returns `bootstrap_secret_required`, and is not compared.
- A configured secret that is missing, empty, or not that same format writes nothing and returns `bootstrap_not_configured`.
- A secret in the query string does not authenticate the claim.
- A non-empty body writes nothing, including a body that contains an email.
- Blank, whitespace-only, and `<OWNER_EMAIL>` configs write nothing and return `owner_not_configured`.
- A wrong secret writes nothing and returns `bootstrap_rejected`.
- The secret compare hashes both values with SHA-256 and uses `crypto.subtle.timingSafeEqual`.
- The first successful claim stores `OWNER_EMAIL` as entered, including letter case and surrounding spaces, with `id = 1` and `claim_source = 'first-boot'`, and inserts one spend row. The response body has no email and no secret.
- The same secret presented again returns `bootstrap_spent` and leaves both rows unchanged.
- Two overlapping claims with the same secret leave exactly one owner row and one spend row.
- A later `OWNER_EMAIL` whose comparison key differs returns `owner_mismatch` and leaves the stored address unchanged.
- A later `OWNER_EMAIL` that differs only by case or surrounding spaces still compares equal, and does not rewrite the stored address.
- A new secret presented while the owner row exists returns `owner_locked`, does not spend that secret, and does not change the row.
- Deleting `owner_lock` does not delete spend rows. The spent secret still returns `bootstrap_spent`. A new secret can claim after that delete.
- `GET /health` does not write.
- The statements the claim handler can issue are the reads and the two `INSERT` statements in this document.
- Logs for these cases contain neither the email nor the secret.

## Operator requirements

- The claim presents a one-time bootstrap secret set with `wrangler secret put`. The first success locks the owner and spends the secret.
- Before that secret is set or the claim is sent, the owner confirms the exact `OWNER_EMAIL` from the private config, that config is deployed, and the deployed var is read back from the Worker script settings and matched. A mismatch stops the procedure with no secret and no claim. The Worker still returns no email and this change still adds no route.
- Mailbox proof is not in the MVP. It remains a future option. The operator owns the Cloudflare account.
- `OWNER_EMAIL` stays a Wrangler var and is personal data that is never logged.
- The email is stored as entered. Comparison uses the trimmed, lowercased key.

Copyright in the foundation documents is Copyright (C) 2026 ADMRN (admrn.com). Contributions require a Developer Certificate of Origin sign-off. Security reports and conduct reports go to hg@admrn.com.
