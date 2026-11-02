# Candidate install (supervised fresh installation)

The v0.1 release requires migration `0008_refresh_token_family.sql` and its matching Worker: D1 tracks each refresh-token family, with one use of the immediately previous token during an approximately 60-second grace period. Owner/family revocation updates `revoked_at` in place and blocks refresh and existing access tokens on their next request. A disabled participant receives temporary HTTP 503 with `Retry-After: 60` and keeps its grant; enabling it resumes the same client.

`POST /owner/claim` returns 500 `internal_error` when `BRIDGE_ORIGIN` is unset or invalid, and 404 `not_found` when the request URL's origin is not `BRIDGE_ORIGIN`. It always refuses `Origin: null`. Otherwise a supplied `Origin` must equal `BRIDGE_ORIGIN`, and a request without `Origin` requires `Sec-Fetch-Site` to be absent or `same-origin`.

For Claude onboarding, use [Claude Basic](design/claude-basic-participant.md) after an authorized rollout of migration 0007. Dot and Claude have separate credentials; Basic includes no engineering lane.

Install one ADMRN Bridge Worker on the operator's own Cloudflare account. The operator's identities, database, KV namespaces, and secrets stay in that account. This repository does not host a bridge.

[docs/test-instance.md](test-instance.md) is a different Worker (`admrn-bridge-test`). Do not follow it for production, and do not point its commands at the production database. Upgrade, rollback, and emergency stop are [docs/upgrade-and-recovery.md](upgrade-and-recovery.md).

Publishing, creating Cloudflare resources, and handling secrets need the owner's approval, as the [README](../README.md) describes. Continuous integration does not run these steps.

Use the published `v0.1.0-rc.1` tag and full 40-character public mirror commit SHA from its release notes. The [README install rule](../README.md#install) requires both. Do not deploy from `main`, a branch tip, or an unchecked tag. If the release is not published, do not install this candidate.

Tracked files use placeholders. The default hostname is the Worker's `workers.dev` name. `bridge.example.com` is only the optional custom-domain example. Put real account ids, database ids, the owner address, and the real hostname only in the gitignored `wrangler.jsonc`. Do not commit them.

## 1. Checkout and local checks

Requires Node.js `^22.13.0 || >=24`.

```sh
git clone https://github.com/vehaize/bridge-basic.git
cd bridge-basic
git fetch origin refs/tags/v0.1.0-rc.1
git rev-parse refs/tags/v0.1.0-rc.1^{commit}
# Compare with the full public mirror commit SHA in the release notes; stop on mismatch.
git checkout --detach <40-character-public-mirror-sha>
git rev-parse HEAD
```

`git rev-parse HEAD` must print that same SHA. If it does not, stop.

```sh
npm ci
npm run lint
npm test
npm run build
```

`npm ci` checks the lockfile integrity hashes. Do not use `npm install` for a release checkout. Release signatures are not available. [docs/release-signing.md](release-signing.md) is the plan. A missing signature is not a reason to skip the SHA check.

## 2. Private Wrangler file

Copy [`wrangler.example.jsonc`](../wrangler.example.jsonc) to `wrangler.jsonc`. That copy is gitignored. Replace every placeholder below. Leave the commented `env.test` block commented. A production deploy that forgets `--env` must still be the production Worker, so the top-level `name` stays `admrn-bridge`.

| Placeholder | Where it appears | What the operator puts there |
| --- | --- | --- |
| `<YOUR_ACCOUNT_ID>` | `account_id` | The operator's Cloudflare account id. |
| `<YOUR_DOMAIN>` | `vars.BRIDGE_ORIGIN` | The public hostname only. The default is `admrn-bridge.<account-subdomain>.workers.dev`. `BRIDGE_ORIGIN` is `https://` plus that hostname, with no userinfo, port, path, query, or fragment. The optional custom domain below uses the same placeholder as its route pattern. |
| `<OWNER_EMAIL>` | `vars.OWNER_EMAIL`, and again inside the commented `env.test` block | The address the first claim will lock. The claim stores the deployed string permanently. |
| `<YOUR_D1_DATABASE_ID>` | `d1_databases` binding `DB` | The id printed by `wrangler d1 create` in section 3. |
| `<YOUR_KV_NAMESPACE_ID>` | `kv_namespaces` binding `KV` | The id printed for the first KV namespace. The Worker does not read binding `KV`. Keep the binding so the private file matches the template. |
| `<YOUR_OAUTH_KV_NAMESPACE_ID>` | `kv_namespaces` binding `OAUTH_KV` | The id printed for the second KV namespace. Dot OAuth grants live here. `/authorize` and `/token` refuse with `oauth_not_configured` when this binding is missing. |
| `1001` | `ratelimits` name `UNAUTHENTICATED_RATE_LIMIT` | A string containing a positive integer unique to the account, for example `"1001"`. Not a descriptive name. A KV namespace id is a hex id Cloudflare issues. Wrangler does not create this id. |
| `1002` | `ratelimits` name `AUTHENTICATED_RATE_LIMIT` | A second string containing a different positive integer unique to the account, for example `"1002"`. Same constraint: not a descriptive name, and not a KV hex id Cloudflare issues. Bindings that share a `namespace_id` share counters. |
| `<YOUR_TEST_D1_DATABASE_ID>` | Commented `env.test` only | Not part of this install. Leave the block commented. |
| `<YOUR_TEST_KV_NAMESPACE_ID>` | Commented `env.test` only | Not part of this install. Leave the block commented. |
| `<YOUR_TEST_OAUTH_KV_NAMESPACE_ID>` | Commented `env.test` only | Not part of this install. Leave the block commented. |

The template sets `workers_dev` to true and leaves `routes` commented out. The default public hostname is `admrn-bridge.<account-subdomain>.workers.dev`. The account subdomain is the one on the operator's Workers & Pages page. `preview_urls` stays false.

Wrangler defaults `workers_dev` to true when the configuration has no `route` or `routes`, and to false when it does. A `routes` entry without an explicit `workers_dev: true` turns the `workers.dev` hostname off on the next deploy. The template sets it true so the default hostname stays on. See [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) and [`workers.dev`](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/).

### Optional custom domain

A custom domain is optional. It needs that hostname's zone on the operator's account. Uncomment `routes` in the private file, set `pattern` to the hostname only (for example `bridge.example.com`), and set `custom_domain` to true. Custom Domains do not use a path. Set `<YOUR_DOMAIN>` to that hostname and `BRIDGE_ORIGIN` to `https://` plus that hostname. This repository does not create the DNS record or the route. Creating them is the owner's step.

Rate limiting by zone WAF needs a custom domain or zone. [Rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) are zone rules. They do not apply to the `workers.dev` hostname, which is not the operator's zone. The Worker rate-limit bindings in this file are separate and stay as written.

The Worker accepts only `BRIDGE_ORIGIN`. When the custom domain is that origin, set `workers_dev` to false so the `workers.dev` name is not a second path. Omitting `workers_dev` while `routes` is set has that same effect, because Wrangler then infers false.

Keep `compatibility_flags` as `nodejs_compat` and `global_fetch_strictly_public`. ChatGPT's client id is a URL, and the OAuth library fetches that document only when `global_fetch_strictly_public` is on.

Keep `invocation_logs` false. Invocation logs store request headers, including `Bootstrap-Secret` and `Authorization`.

Keep both rate-limit bindings. `simple.limit` and `simple.period` match `UNAUTHENTICATED_RATE_LIMIT` (60), `AUTHENTICATED_RATE_LIMIT` (120), and `RATE_LIMIT_PERIOD_SECONDS` (60) in `src/provisional.ts`. The binding is free on Workers and has no per-call charge. There is no CPU time cap.

A missing or rejected `UNAUTHENTICATED_RATE_LIMIT` or `AUTHENTICATED_RATE_LIMIT` binding makes a charged request return HTTP 503 and `{"ok":false,"error":"rate_limit_unavailable"}`. Charged routes are `POST /token`, `POST /mcp`, a `POST /owner/claim` that presents a well-formed `Bootstrap-Secret` and passes the site check, and a `POST /authorize` that passes the OAuth prefilter and the consent site check. `GET /authorize` does not spend the address bucket. A cross-site or same-site `POST /authorize` or `POST /owner/claim` returns 403 and does not spend it. The consent site check also accepts `Origin: null` together with `Sec-Fetch-Site: same-origin`, the pair a browser can send for the consent form when a referrer policy withholds the page's origin. The consent page is served with `Referrer-Policy: same-origin`. `Origin: null` with any other `Sec-Fetch-Site`, or with none, returns 403 and does not spend the bucket. That exception is for `POST /authorize` only: `POST /owner/claim` refuses `Origin: null` with 403 even with `Sec-Fetch-Site: same-origin`. A method, path, or content type the route rejects is not counted. `GET /health` and the OAuth discovery routes do not use these bindings. HTTP 429 `rate_limited` is a different response: the binding worked and the caller exceeded the limit.

The template registers one cron, `0 0 * * *` (`RETENTION_CRON`). A deploy runs retention once a day: it stores `expired` on rows past their deadline, then deletes a finished row 30 days after its last change. Workers Free allows five crons per account. Nothing in this repository deletes a remote database.

Worker secrets are not vars in this file. The names the Worker reads are `BOOTSTRAP_SECRET` and `WAKE_SECRET_GROK_BOT`. Local placeholders for `wrangler dev` are [`.dev.vars.example`](../.dev.vars.example). Production uses `wrangler secret put`, in the sections below.

## 3. Create D1 and the two KV namespaces

Create the resources in the operator's account after `account_id` is set. These commands create remote resources. Read each command before you run it.

```sh
wrangler d1 create admrn-bridge --config wrangler.jsonc
wrangler kv namespace create admrn-bridge --config wrangler.jsonc
wrangler kv namespace create admrn-bridge-oauth --config wrangler.jsonc
```

Wrangler prints a database id and two namespace ids. Copy them into `wrangler.jsonc` as `database_id`, the `KV` id, and the `OAUTH_KV` id. `admrn-bridge` is the D1 database name and the KV namespace for binding `KV`. `admrn-bridge-oauth` is the KV namespace for binding `OAUTH_KV`.

If a command reports that the name already exists, stop. Reuse it only when the owner confirms it is this production resource and not the test database `admrn-bridge-test`. Otherwise pick a new name, put that name in the private file, and use it in later commands. The binding names stay `DB`, `KV`, and `OAUTH_KV`.

There is no create command for the rate-limit namespace ids. Choose two different strings, each a positive integer unique to the account, and write them into the private file. A descriptive name is not a `namespace_id`. A KV namespace id is a hex id Cloudflare issues.

## 4. Migrations

Schema changes use one command. `DB` is the binding name. Wrangler resolves it through `wrangler.jsonc`. Read `database_name` before you confirm. For this install it is `admrn-bridge`. If it is `admrn-bridge-test`, stop.

```sh
wrangler d1 migrations list DB --remote --config wrangler.jsonc
wrangler d1 migrations apply DB --remote --config wrangler.jsonc
wrangler d1 migrations list DB --remote --config wrangler.jsonc
```

`migrations apply` runs each pending file under `migrations/` and records that filename in the `d1_migrations` table (`id`, `name`, `applied_at`). The name is the filename, such as `0001_owner_lock.sql`. In a terminal the command asks for confirmation and tells you the database may be unavailable while a file runs. Read that output before accepting. A non-interactive shell skips the confirmation. Wrangler sends each file together with the insert into `d1_migrations`. A file that fails is not left recorded. Files that already succeeded stay recorded.

The second `migrations list` prints `No migrations to apply!` when every file under `migrations/` is recorded. Any other output means at least one file is still pending. `GET /health` does not report this. See section 7.

Do not apply `migrations/*.sql` with `wrangler d1 execute --file`. That command can run the SQL without inserting `d1_migrations`. A later `migrations apply` then tries to create objects that already exist and stops, while `migrations list` still shows the files as pending.

`0001_owner_lock.sql` creates `owner_lock` and `bootstrap_secret_spend`. `0002_item_lifecycle.sql` creates `item`. `0003_participant_credentials.sql` creates `participant` and `participant_credential` and seeds `grok_bot` and `dot` with `enabled = 1`. `0004_connect_code.sql` creates `connect_code`. `0005_item_receipt.sql` adds a nullable `delivered_at` column to `item`. `0006_authority_envelope.sql` adds immutable envelopes and the audit log. `0007_claude_basic_participant.sql` adds Claude and preserves existing rows and schema protections. None of these files contains a code, a hash, or an email. None of them has a down file. Rolling back the Worker does not drop a table or remove `delivered_at`.

`0006_authority_envelope.sql` rebuilds `item` with nullable `envelope_json` and `envelope_sha256` and creates `item_audit` and `item_audit_head`. It has no down file. A file added after it is applied by the same command.

Generated credential SQL is not a migration. Sections 8 and 9 apply those files with `wrangler d1 execute --file`. Do not copy them into `migrations/`.

### A database that was loaded with `d1 execute --file`

If 0001–0005 were already applied that way, do not run `migrations apply` until the baseline rows below are recorded. Before those rows exist, that command tries to create objects that are already there and stops, and `migrations list` still shows those files as pending.

1. Run `migrations list` once. That creates an empty `d1_migrations` table when the table is missing, then prints every filename under `migrations/` as pending. The names include the five baseline files and any later file, such as `0006_authority_envelope.sql` or a file added after it.

2. Confirm the baseline objects are present: `owner_lock`, `bootstrap_secret_spend`, `item`, `participant`, `participant_credential`, `connect_code`, and the column `item.delivered_at`. Record the baseline filenames whose objects are present:

   ```sh
   wrangler d1 execute DB --remote --config wrangler.jsonc --command "INSERT INTO d1_migrations (name) VALUES ('0001_owner_lock.sql'), ('0002_item_lifecycle.sql'), ('0003_participant_credentials.sql'), ('0004_connect_code.sql'), ('0005_item_receipt.sql');"
   ```

   If one of those five files has objects missing, do not insert that filename. Repair is a forward fix or a Time Travel restore, as [docs/upgrade-and-recovery.md](upgrade-and-recovery.md) describes.

3. After that verified baseline is recorded, list the remaining pending migrations:

   ```sh
   wrangler d1 migrations list DB --remote --config wrangler.jsonc
   ```

   Each name in this list is still pending. That is expected while a later file has no row. Handle every name before you treat the database as migrated.

4. Decide each pending file from its objects. `0006_authority_envelope.sql` adds tables `item_audit` and `item_audit_head`, columns `item.envelope_json` and `item.envelope_sha256`, the `item_audit_*` indexes, and the triggers in that file. Check them with one query:

   ```sh
   wrangler d1 execute DB --remote --config wrangler.jsonc --command "SELECT (SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'item_audit') AS item_audit, (SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'item_audit_head') AS item_audit_head, (SELECT count(*) FROM pragma_table_info('item') WHERE name = 'envelope_json') AS envelope_json, (SELECT count(*) FROM pragma_table_info('item') WHERE name = 'envelope_sha256') AS envelope_sha256, (SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name IN ('item_audit_expiry', 'item_audit_delivery', 'item_audit_rejection_cap')) AS audit_indexes, (SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('item_envelope_immutable', 'item_no_replace', 'item_no_replace_update', 'item_audit_head_no_replace', 'item_audit_head_block_update', 'item_audit_head_block_delete', 'item_audit_no_replace', 'item_audit_one_expiry', 'item_audit_one_delivery', 'item_audit_block_update', 'item_audit_block_delete', 'item_audit_head_advance')) AS triggers;"
   ```

   `audit_indexes` is `3`, one for each `CREATE INDEX` on `item_audit` in `migrations/0006_authority_envelope.sql`. `triggers` is `12`, one for each `CREATE TRIGGER` in that file. All six values `0` means the objects are absent. The values `1`, `1`, `1`, `1`, `3`, `12` mean the objects are present. Any other mix means stop. Do not apply that file and do not insert its name. The file aborts when `item_audit` or `item.envelope_json` already exists. Continuing past that error rebuilds `item` and stores null envelopes.

   When those values show the objects are present, confirm the head row before you record the name:

   ```sh
   wrangler d1 execute DB --remote --config wrangler.jsonc --command "SELECT id, seq FROM item_audit_head;"
   ```

   The result is one row and `id` is `1`. Any other result means stop. Do not apply that file and do not insert its name.

   A file added after `0006_authority_envelope.sql` uses the same rule. Read that file. Its objects are absent when none of the tables, columns, indexes, or triggers it creates are in the database, and present when every one of those objects is there. A mix means stop for that file. Do not apply it and do not insert its name.

5. When a pending file's objects are already present, verify them and record the filename the same way as the baseline. Do this for every such file before you apply. For `0006_authority_envelope.sql` the statement is:

   ```sh
   wrangler d1 execute DB --remote --config wrangler.jsonc --command "INSERT INTO d1_migrations (name) VALUES ('0006_authority_envelope.sql');"
   ```

   A later file whose objects are already present uses that same statement with its own filename.

6. When a pending file's objects are absent, apply the files that are still pending:

   ```sh
   wrangler d1 migrations apply DB --remote --config wrangler.jsonc
   ```

   That is safe at that point, because the baseline rows mean only the remaining files run. Record every pending file whose objects are already present first, so this command does not try to create them. Read the database name before you accept the confirmation. For this install it is `admrn-bridge`. Wrangler runs each still-pending file together with its `d1_migrations` insert. A file that fails is not left recorded. If every remaining file was recorded in the previous step, skip this command.

7. When every pending name has been applied or recorded, list again:

   ```sh
   wrangler d1 migrations list DB --remote --config wrangler.jsonc
   ```

   Only this list must print `No migrations to apply!`.

Apply migrations before the first claim, and before any deploy of code that reads the new schema.

## 5. Deploy, read `OWNER_EMAIL` back, then claim

Follow [Confirm the owner email](design/owner-lock.md#confirm-the-owner-email) and [Secret lifetime](design/owner-lock.md#secret-lifetime) in this order. The claim writes the deployed `OWNER_EMAIL` into `owner_lock` once. A later deploy does not change that row. The same address again is `owner_locked`. A different address is `owner_mismatch`. A wrong value stays until the owner follows the reset in that design.

The secret name is `BOOTSTRAP_SECRET`. This page does not contain a value. The value is 32 bytes from `crypto.getRandomValues`, base64url without padding: 43 characters from `A-Za-z0-9_-`. A passphrase is not a bootstrap secret.

1. Read `OWNER_EMAIL` from `wrangler.jsonc` and show the owner that exact string, in full, in the owner's own chat. The read-back is not logged. Wait for an explicit confirmation of that string. If the owner does not confirm it, or the confirmation differs, stop. Leave the secret unset and send no claim.
2. Deploy that private file. This deploy has no `BOOTSTRAP_SECRET`:

   ```sh
   wrangler deploy --config wrangler.jsonc
   ```

3. Read `OWNER_EMAIL` from the deployed Worker. The control-plane read is the `plain_text` binding on `GET /accounts/{account_id}/workers/scripts/admrn-bridge/settings`. The script name is `admrn-bridge`. It is not a Worker response, and it is not logged.
4. If that deployed string is not the exact string the owner confirmed, stop. Put no secret and send no claim.
5. Generate the secret only after that match. Use one shell for the rest of this section so the path variables stay set. The commands write files outside the clone. They do not print the secret and do not pass it as a Wrangler argument. `umask 077` makes those files mode `0600`. A failed check stops the chain.

   ```sh
   secret="$HOME/admrn-bootstrap-secret"
   header="$HOME/admrn-claim-header"
   (umask 077; node --input-type=module > "$secret" <<'EOF'
   import { webcrypto } from "node:crypto";
   const bytes = new Uint8Array(32);
   webcrypto.getRandomValues(bytes);
   process.stdout.write(Buffer.from(bytes).toString("base64url"));
   EOF
   ) && test "$(wc -c < "$secret")" -eq 43 && grep -qE '^[A-Za-z0-9_-]{43}$' "$secret"
   ```

6. Set the secret from that file. No other deploy comes between the matching read and this command. Wrangler reads stdin and trims trailing whitespace.

   ```sh
   wrangler secret put BOOTSTRAP_SECRET --config wrangler.jsonc < "$secret"
   ```

7. Read the origin from the private file, then send one claim. The body is empty. The header file is mode `0600` and is not a curl argument. Stop when the origin is empty or still contains a placeholder.

   ```sh
   BRIDGE_ORIGIN="$(node --input-type=module <<'EOF'
   import { readFileSync } from "node:fs";
   const raw = readFileSync("wrangler.jsonc", "utf8")
     .replace(/\/\*[\s\S]*?\*\//g, "")
     .replace(/^\s*\/\/.*$/gm, "")
     .replace(/,\s*([}\]])/g, "$1");
   const origin = JSON.parse(raw).vars?.BRIDGE_ORIGIN;
   if (typeof origin !== "string") process.exit(1);
   process.stdout.write(origin);
   EOF
   )"
   test -n "$BRIDGE_ORIGIN" || { printf '%s\n' "BRIDGE_ORIGIN is not set" >&2; exit 1; }
   case "$BRIDGE_ORIGIN" in
     *'<YOUR_DOMAIN>'*|https://bridge.example.com|https://bridge.example.com/) printf '%s\n' "BRIDGE_ORIGIN is still a placeholder or the documented example hostname" >&2; exit 1 ;;
   esac
   (umask 077; { printf 'Bootstrap-Secret: '; cat "$secret"; printf '\n'; } > "$header")
   curl -sS -D - -o "$HOME/admrn-claim-body" -X POST \
     -H @"$header" \
     "$BRIDGE_ORIGIN/owner/claim"
   ```

   A successful claim is HTTP `201` and a body of `{"locked":true}`. The body has no email and no secret.
8. Delete the local files. Then delete the Worker secret. Do this after every claim attempt, including a non-201, a timeout, or no response.

   ```sh
   rm -f "$secret" "$header"
   wrangler secret delete BOOTSTRAP_SECRET --config wrangler.jsonc
   wrangler secret list --config wrangler.jsonc
   ```

   The list prints names, not values. `BOOTSTRAP_SECRET` must be absent. Re-read `owner_lock` and `bootstrap_secret_spend` from the primary before any retry. A spend row for the secret just used means stop. Upload a new secret only when `owner_lock` is absent, as [Secret lifetime](design/owner-lock.md#secret-lifetime) requires.

Delete `$HOME/admrn-claim-body` after reading the status. It is not a secret, and it does not belong in the clone.

## 6. Read the deployed version

`GET /health` is unauthenticated and static. It returns `ok`, `service`, `phase`, `status`, and `mvp`. It does not return a git SHA, a Worker version id, an environment name, the owner email, or any binding. An MCP `initialize` result has `serverInfo.version` `0.0.0`, which is a constant in the adapter, not the deployed commit.

Read the deployment from Wrangler. `deployments list` shows the ten most recent Worker versions. `deployments status` shows the version that is current. Neither command reads a git SHA out of the Worker. The operator matches a deployment to the tag they deployed by the checkout they used for `wrangler deploy`.

```sh
curl -sS "$BRIDGE_ORIGIN/health"
wrangler deployments list --config wrangler.jsonc
wrangler deployments status --config wrangler.jsonc
```

In a new shell, set `BRIDGE_ORIGIN` again with the command in section 5 before the curl.

## 7. Detect missing migrations

`GET /health` stays `200` when the schema is behind the code. Use the migration list:

```sh
wrangler d1 migrations list DB --remote --config wrangler.jsonc
```

`No migrations to apply!` means every file under `migrations/` has a row in `d1_migrations`. A table of filenames means those files are not recorded. That is the check. Do not infer a missing migration from `/health`.

When code that reads items is deployed and `item.delivered_at` is absent, item tool calls fail closed. The tool result is `internal_error`. The log event is `mcp.refused` with reason `receipt_column_absent`. That reason means migration `0005_item_receipt.sql` is not in the database. Earlier missing objects also fail the request. They do not use that reason. The list command is still the check.

Apply the pending files with section 4 before deploying code that needs them. If the objects already exist because someone used `d1 execute --file`, reconcile `d1_migrations` as section 4 describes. In that case, do not run `migrations apply` until that section's baseline rows are recorded, and do not run it on top of objects that are already there. After the baseline is recorded, the command runs only the pending files that remain.

## 8. Grok credential

Issue the bearer only after the owner lock exists. [`scripts/grok-credential.mjs`](../scripts/grok-credential.mjs) writes SQL and prints the token once on stdout. It does not apply the file and it does not call Cloudflare. The token is `admrn_gb_` plus 43 base64url characters. The SQL file holds the SHA-256, not the token. Issuing revokes any active Grok bearer and inserts the new one. Items stay with the participant.

The command's own comment names `wrangler d1 execute admrn-bridge`. Use the binding and the private config so the database is the one in `wrangler.jsonc`. Read `database_name` before you run it.

```sh
grok_sql="$HOME/grok-credential.sql"
grok_token="$HOME/grok-token"
(umask 077; node scripts/grok-credential.mjs issue --out "$grok_sql" > "$grok_token") \
  && test "$(wc -c < "$grok_token")" -eq 53 \
  && wrangler d1 execute DB --remote --config wrangler.jsonc --file "$grok_sql" \
  && rm -f "$grok_sql"
```

Stdout is the token plus a newline, so the file is 53 bytes. If the length check fails, delete `$HOME/grok-token` and `$HOME/grok-credential.sql` and stop. The apply did not run. Keep the token file outside the clone until it is stored in the operator's Grok Bot, then delete it. Do not commit it, paste it into chat, or pass it as a command argument.

Accepted for the MVP: with xAI's API remote MCP tool, xAI's servers make the MCP call, so this bearer passes through xAI's servers on every request. To keep the token on the user's own machine, use Grok Build or custom code that holds the token locally instead of pasting it into a hosted chat.

Configure that bot with [templates/grok-bot/](../templates/grok-bot/). The MCP endpoint is `$BRIDGE_ORIGIN/mcp`. The bot sends `Authorization: Bearer` and the token. Revoke later with `node scripts/grok-credential.mjs revoke --out <file>` and apply that file the same way. `revoke` prints nothing.

This `d1 execute --file` is credential SQL, not a schema migration. It does not insert `d1_migrations`.

## 9. Dot connect code

Dot connects from the owner's own ChatGPT, in the account where Dot runs, using ChatGPT's custom MCP connector. The server URL is `$BRIDGE_ORIGIN/mcp`. Authentication is OAuth. An API key or a connector with no authentication is the wrong setup.

Start the connection from that ChatGPT. ChatGPT opens `$BRIDGE_ORIGIN/authorize`. The page says `chatgpt.com will connect as Dot` and shows redirect URI `https://chatgpt.com/connector_platform_oauth_redirect`. It shows no email and no item.

Before pasting a code, view the page source. For Dot, require client id `https://chatgpt.com/oauth/client.json`. Claude uses a separate fixed client and connect code; see [Claude Basic](design/claude-basic-participant.md). A crossed client/redirect pair or unknown client means stop. The private notes a test run records are in [test-instance.md](test-instance.md) section 7. Those notes stay out of the repository. Do not run the test-instance commands against this database.

[`scripts/connect-code.mjs`](../scripts/connect-code.mjs) prints the code once and writes SQL. It does not apply the file. The ten minutes start when the SQL file is applied, not when the command runs. Equality at `expires_at` is expired. Apply it immediately, then paste the code only into the connect-code field on the tab ChatGPT just opened.

```sh
code_sql="$HOME/connect-code.sql"
code_file="$HOME/connect-code"
(umask 077; node scripts/connect-code.mjs issue --out "$code_sql" > "$code_file") \
  && test "$(wc -c < "$code_file")" -eq 44 \
  && wrangler d1 execute DB --remote --config wrangler.jsonc --file "$code_sql"
```

The code file is 43 characters plus the newline stdout adds. If the length check fails, delete both files and stop. The apply did not run. After submit, delete both files:

```sh
rm -f "$code_sql" "$code_file"
```

If the consent page was the wrong client, or the code was displayed anywhere other than that tab, expire it instead of pasting:

```sh
node scripts/connect-code.mjs expire --out "$HOME/connect-code-expire.sql"
wrangler d1 execute DB --remote --config wrangler.jsonc --file "$HOME/connect-code-expire.sql"
rm -f "$HOME/connect-code-expire.sql" "$code_sql" "$code_file"
```

`expire` prints nothing. It does not disconnect a Dot that already finished `/authorize`. A later successful code does that, because spending a code revokes the previous Dot credential.

After ChatGPT returns from the redirect, ask Dot to call `list_items` with `box` `inbox`. This execute is credential SQL, not a schema migration.

## 10. Wake, optional

Wakes stay off until `participant.wake_url` for `grok_bot` is an https URL with no userinfo, query, or fragment, and the Worker secret `WAKE_SECRET_GROK_BOT` is set. The secret is `whsec_` plus the standard base64 of 32 random bytes. It is not a var in the example file. Set it with `wrangler secret put WAKE_SECRET_GROK_BOT --config wrangler.jsonc` and do not put the value in git, chat, or this page.

The signed body has only `type`, `item_id`, and `occurred_at`. A missing URL logs `not_configured`. A missing or malformed secret logs `no_secret` and sends nothing. Polling `list_items` and `get_item` is how a participant sees items. The wake is a best-effort hint. The [Grok Bot template](../templates/grok-bot/README.md) says the same thing to the bot.

`wrangler secret list --config wrangler.jsonc` must not include `BOOTSTRAP_SECRET` after section 5. `WAKE_SECRET_GROK_BOT` is present only when the operator chose to set it. The private Wrangler file stays uncommitted.
