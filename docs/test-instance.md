# Test instance

The v0.1 release requires migration `0008_refresh_token_family.sql` and its matching Worker: D1 tracks each refresh-token family, with one use of the immediately previous token during an approximately 60-second grace period. Owner/family revocation updates `revoked_at` in place and blocks refresh and existing access tokens on their next request. A disabled participant receives temporary HTTP 503 with `Retry-After: 60` and keeps its grant; enabling it resumes the same client.

`POST /owner/claim` returns 500 `internal_error` when `BRIDGE_ORIGIN` is unset or invalid, and 404 `not_found` when the request URL's origin is not `BRIDGE_ORIGIN`. It always refuses `Origin: null`. Otherwise a supplied `Origin` must equal `BRIDGE_ORIGIN`, and a request without `Origin` requires `Sec-Fetch-Site` to be absent or `same-origin`.

Operator runbook for one private test Worker. It is not the production install. Continuous integration does not run these steps. Publishing, creating Cloudflare resources, and handling secrets need the owner's approval, as [the README](../README.md) describes.

Tracked examples use `bridge-test.example.invalid` only for the optional custom domain. It does not resolve. The default hostname is the test Worker's `workers.dev` name, `admrn-bridge-test.<account-subdomain>.workers.dev`. Put the real test hostname only in the private Wrangler file, and do not commit that hostname. The account subdomain is confirmed in the owner's go-live session. Creating a DNS record and a Worker route is a live step only for the optional custom domain; this runbook only documents it. Do not write an account id, an email address, a database id, or a secret into this repository.

The private file is `wrangler.test.jsonc` in the clone. `wrangler.*.jsonc` is gitignored. Use that filename on every Wrangler command below. A deploy of `wrangler.jsonc` or of [`wrangler.example.jsonc`](../wrangler.example.jsonc) is a different Worker.

## 1. Private Wrangler file

Copy `wrangler.example.jsonc` to `wrangler.test.jsonc`. The commented `env.test` block in the example is a reminder of the distinct names. Leave it commented. Change the top-level fields of the private copy. A deploy that forgets `--env` must still target the test Worker, so the top-level `name` itself is `admrn-bridge-test`.

Set these fields:

```jsonc
"name": "admrn-bridge-test",
"compatibility_flags": ["nodejs_compat", "global_fetch_strictly_public", "enable_request_signal"],
"account_id": "<YOUR_ACCOUNT_ID>",
"workers_dev": true,
"preview_urls": false,
"vars": {
  "OWNER_EMAIL": "<OWNER_EMAIL>",
  "BRIDGE_ORIGIN": "https://admrn-bridge-test.<YOUR_SUBDOMAIN>.workers.dev"
},
"d1_databases": [
  {
    "binding": "DB",
    "database_name": "admrn-bridge-test",
    "database_id": "<YOUR_TEST_D1_DATABASE_ID>"
  }
],
"kv_namespaces": [
  { "binding": "KV", "id": "<YOUR_TEST_KV_NAMESPACE_ID>" },
  { "binding": "OAUTH_KV", "id": "<YOUR_TEST_OAUTH_KV_NAMESPACE_ID>" }
]
```

Keep `global_fetch_strictly_public`. ChatGPT's client id is a URL, and the OAuth library fetches that document only when this flag is on. Keep `nodejs_compat`. Keep `enable_request_signal`. It aborts `request.signal` when the client disconnects, so a Connect submit can clear its pending claim. Without that flag, disconnect cleanup does not run. The 10-second claim lease still releases the code. Keep `workers_dev` true for the default `workers.dev` path. Keep `preview_urls` false. Keep `invocation_logs` false. Invocation logs store request headers, including `Bootstrap-Secret` and `Authorization`.

`BRIDGE_ORIGIN` is the public https origin with no userinfo, port, path, query, or fragment. On the default path it is `https://` plus `admrn-bridge-test.<account-subdomain>.workers.dev`. Replace `<YOUR_SUBDOMAIN>` in the private file with the account subdomain from Workers & Pages. This repository does not create that hostname. Wrangler publishes it when `workers_dev` is true and the config has no `routes`. If `routes` is set and `workers_dev` is omitted, Wrangler infers `workers_dev` false. The template sets `workers_dev` true so the default hostname stays on. See [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/).

### Optional custom domain

A custom domain is optional. It needs that hostname's zone on the operator's account. Rate limiting by zone WAF needs a custom domain or zone. [Rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) are zone rules. They do not apply to `workers.dev`, which is not the operator's zone. See [`workers.dev`](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/).

To use one, set the route and point `BRIDGE_ORIGIN` at that hostname. The anonymized example does not resolve:

```jsonc
"routes": [
  { "pattern": "bridge-test.example.invalid", "custom_domain": true }
],
"vars": {
  "OWNER_EMAIL": "<OWNER_EMAIL>",
  "BRIDGE_ORIGIN": "https://bridge-test.example.invalid"
}
```

The Worker accepts only `BRIDGE_ORIGIN`. When that origin is the custom domain, set `workers_dev` to false so the `workers.dev` name is not a second path. Creating the DNS record and the route is a live step in the go-live session. This runbook only documents that step: this repository does not create the record, attach the route, or call Cloudflare.

Read the private origin into the shell before any curl. Run this from the clone. Repeat it in a new shell. Stop when the value is empty, still contains `example.invalid`, or still contains `<YOUR_SUBDOMAIN>`:

```sh
BRIDGE_ORIGIN="$(node --input-type=module <<'EOF'
import { readFileSync } from "node:fs";
const raw = readFileSync("wrangler.test.jsonc", "utf8")
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
  *example.invalid*|*'<YOUR_SUBDOMAIN>'*) printf '%s\n' "BRIDGE_ORIGIN is still the anonymized example" >&2; exit 1 ;;
esac
```

Every curl below uses `$BRIDGE_ORIGIN`. Build the ChatGPT connector URL from that same variable.

`OWNER_EMAIL` in this repository stays the placeholder `<OWNER_EMAIL>`. In the private file, replace that placeholder with the owner address. The claim stores the deployed string permanently. Section 4 reads it back before any secret is set.

Replace `<YOUR_ACCOUNT_ID>` in the private file with the operator's account id. Leave the test database and KV ids as placeholders until section 2 returns them. Put those ids only in the private file.

The binding names stay `DB`, `KV`, and `OAUTH_KV`. The Cloudflare resource names are the distinct ones above: Worker `admrn-bridge-test`, D1 `admrn-bridge-test`, and two KV namespaces that are not the production namespaces.

The example also has `UNAUTHENTICATED_RATE_LIMIT` and `AUTHENTICATED_RATE_LIMIT`. Replace `1001` and `1002` with two different strings. Each `namespace_id` must be a string containing a positive integer unique to the account (for example `"1001"`), not a descriptive name. A KV namespace id is a hex id Cloudflare issues. Wrangler does not create a rate-limit namespace id. A missing or rejected binding makes an accepted `POST /token`, `POST /owner/claim`, or `POST /mcp`, and a `POST /authorize` that passes the OAuth prefilter and the consent site check, return 503 with reason `rate_limit_unavailable`. `GET /authorize` does not spend the address bucket. A cross-site or same-site `POST /authorize` returns 403 and does not spend it. A POST with neither `Origin` nor `Sec-Fetch-Site` is counted, the same way the consent handler already accepts that request. A `POST /authorize` with `Origin: null` is accepted and counted only together with `Sec-Fetch-Site: same-origin`. With any other `Sec-Fetch-Site`, or with none, it returns 403 and is not counted. A cross-site or same-site `POST /owner/claim` returns 403 and does not spend the address bucket. The `Origin: null` exception is for the consent route only: `POST /owner/claim` with `Origin: null` returns 403 even with `Sec-Fetch-Site: same-origin`. That claim spends the bucket only when it also presents a well-formed `Bootstrap-Secret`. `GET /health` and the OAuth discovery routes do not use the binding. There is no CPU time cap.

Wakes stay off until `participant.wake_url` for `grok_bot` is an https URL with no userinfo, query, or fragment, and the Worker secret `WAKE_SECRET_GROK_BOT` is set. The secret is `whsec_` plus the standard base64 of 32 random bytes. It is not a var in the example file. The signed body has only `type`, `item_id`, and `occurred_at`. A missing URL logs `not_configured`. A missing or malformed secret logs `no_secret` and sends nothing.

The example registers one daily cron, `0 0 * * *`. A deploy of that config runs retention once a day: it stores `expired` on rows past their deadline, then deletes a finished row 30 days after its last change. CI does not run the cron, and no command in this repository deletes a remote database.

## 2. Test D1, KV, and OAUTH_KV

Create the resources in the operator's account after the private file has the account id. These commands create remote resources. Read each command before you run it. The names are the test names.

```sh
wrangler d1 create admrn-bridge-test --config wrangler.test.jsonc
wrangler kv namespace create admrn-bridge-test --config wrangler.test.jsonc
wrangler kv namespace create admrn-bridge-test-oauth --config wrangler.test.jsonc
```

Wrangler prints a database id and two namespace ids. Copy them into `wrangler.test.jsonc` as `database_id`, the `KV` id, and the `OAUTH_KV` id. `admrn-bridge-test` is the D1 database and the KV namespace for binding `KV`. `admrn-bridge-test-oauth` is the KV namespace for binding `OAUTH_KV`.

If a command reports that the name already exists, stop. Confirm it is an old test resource and not the production database `admrn-bridge` or the production KV namespaces. Reuse it only when the owner confirms it is the test resource. Otherwise pick a new test name and use that name in the private file and in every later command.

## 3. Migrations on the test D1 only

Apply every file under `migrations/` to the test D1 database and to no other database. Schema files in `migrations/` use the same command as [the production install](install.md): `wrangler d1 migrations apply`. The database argument `DB` is the binding. Wrangler resolves it through `wrangler.test.jsonc`. Read `database_name` in that file before you confirm the command. If it is `admrn-bridge`, stop. It must be `admrn-bridge-test`.

`wrangler d1 migrations apply` runs each pending file and records that filename in `d1_migrations`. `wrangler d1 migrations list` prints `No migrations to apply!` when every file is recorded, and otherwise prints the filenames still pending. Do not apply `migrations/*.sql` with `wrangler d1 execute --file`. That command can run the SQL without inserting `d1_migrations`. A later `migrations apply` then tries to create objects that already exist and stops, while `migrations list` still shows the files as pending.

Sections 6 and 7 still use `wrangler d1 execute --file` for the SQL written by `scripts/grok-credential.mjs` and `scripts/connect-code.mjs`. Those files are not migrations. They must not be copied into `migrations/`, and they do not update `d1_migrations`. `d1 execute --file` remains the way to apply one generated credential file as one transaction.

```sh
wrangler d1 migrations list DB --remote --config wrangler.test.jsonc
wrangler d1 migrations apply DB --remote --config wrangler.test.jsonc
wrangler d1 migrations list DB --remote --config wrangler.test.jsonc
```

The second list prints `No migrations to apply!` when every file under `migrations/` is recorded. A later file that is still pending means the list is not empty. `migrations apply` asks for confirmation in a terminal. Read the printed database before accepting. Wrangler runs each file together with its `d1_migrations` insert. A file that fails is not left recorded. Files that already succeeded stay recorded.

`0001_owner_lock.sql` creates `owner_lock` and `bootstrap_secret_spend`. `0002_item_lifecycle.sql` creates `item`. `0003_participant_credentials.sql` creates `participant` and `participant_credential` and seeds `grok_bot` and `dot`. `0004_connect_code.sql` creates `connect_code`. `0005_item_receipt.sql` adds a nullable `delivered_at` column to `item`. None of these files contains a code, a hash, or an email. None of them has a down file.

`0006_authority_envelope.sql` rebuilds `item` with nullable `envelope_json` and `envelope_sha256` and creates `item_audit` and `item_audit_head`. It has no down file. A file added after it is applied by the same command.

`0005_item_receipt.sql` has no down file. Rolling back the Worker does not remove `delivered_at`. The column stays on `item`.

If this test database already received 0001–0005 through `wrangler d1 execute --file`, do not run `migrations apply` until the baseline rows below are recorded. Before those rows exist, that command tries to create objects that are already there and stops, and `migrations list` still shows those files as pending.

1. Run `migrations list` once. That creates an empty `d1_migrations` table when the table is missing, then prints every filename under `migrations/` as pending. The names include the five baseline files and any later file, such as `0006_authority_envelope.sql` or a file added after it.

2. Confirm the baseline objects are present: `owner_lock`, `bootstrap_secret_spend`, `item`, `participant`, `participant_credential`, `connect_code`, and the column `item.delivered_at`. Record the baseline filenames whose objects are present:

   ```sh
   wrangler d1 execute DB --remote --config wrangler.test.jsonc --command "INSERT INTO d1_migrations (name) VALUES ('0001_owner_lock.sql'), ('0002_item_lifecycle.sql'), ('0003_participant_credentials.sql'), ('0004_connect_code.sql'), ('0005_item_receipt.sql');"
   ```

   If one of those five files has objects missing, stop and do not insert that filename. Repair is a forward fix or a restore, as [docs/upgrade-and-recovery.md](upgrade-and-recovery.md) describes, not a second apply of a half-recorded name.

3. After that verified baseline is recorded, list the remaining pending migrations:

   ```sh
   wrangler d1 migrations list DB --remote --config wrangler.test.jsonc
   ```

   Each name in this list is still pending. That is expected while a later file has no row. Handle every name before you treat the database as migrated.

4. Decide each pending file from its objects. `0006_authority_envelope.sql` adds tables `item_audit` and `item_audit_head`, columns `item.envelope_json` and `item.envelope_sha256`, the `item_audit_*` indexes, and the triggers in that file. Check them with one query:

   ```sh
   wrangler d1 execute DB --remote --config wrangler.test.jsonc --command "SELECT (SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'item_audit') AS item_audit, (SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'item_audit_head') AS item_audit_head, (SELECT count(*) FROM pragma_table_info('item') WHERE name = 'envelope_json') AS envelope_json, (SELECT count(*) FROM pragma_table_info('item') WHERE name = 'envelope_sha256') AS envelope_sha256, (SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name IN ('item_audit_expiry', 'item_audit_delivery', 'item_audit_rejection_cap')) AS audit_indexes, (SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('item_envelope_immutable', 'item_no_replace', 'item_no_replace_update', 'item_audit_head_no_replace', 'item_audit_head_block_update', 'item_audit_head_block_delete', 'item_audit_no_replace', 'item_audit_one_expiry', 'item_audit_one_delivery', 'item_audit_block_update', 'item_audit_block_delete', 'item_audit_head_advance')) AS triggers;"
   ```

   `audit_indexes` is `3`, one for each `CREATE INDEX` on `item_audit` in `migrations/0006_authority_envelope.sql`. `triggers` is `12`, one for each `CREATE TRIGGER` in that file. All six values `0` means the objects are absent. The values `1`, `1`, `1`, `1`, `3`, `12` mean the objects are present. Any other mix means stop. Do not apply that file and do not insert its name. The file aborts when `item_audit` or `item.envelope_json` already exists. Continuing past that error rebuilds `item` and stores null envelopes.

   When those values show the objects are present, confirm the head row before you record the name. Read `database_name` before you run the query. If it is `admrn-bridge`, stop.

   ```sh
   wrangler d1 execute DB --remote --config wrangler.test.jsonc --command "SELECT id, seq FROM item_audit_head;"
   ```

   The result is one row and `id` is `1`. Any other result means stop. Do not apply that file and do not insert its name.

   A file added after `0006_authority_envelope.sql` uses the same rule. Read that file. Its objects are absent when none of the tables, columns, indexes, or triggers it creates are in the database, and present when every one of those objects is there. A mix means stop for that file. Do not apply it and do not insert its name.

5. When a pending file's objects are already present, verify them and record the filename the same way as the baseline. Do this for every such file before you apply. For `0006_authority_envelope.sql` the statement is:

   ```sh
   wrangler d1 execute DB --remote --config wrangler.test.jsonc --command "INSERT INTO d1_migrations (name) VALUES ('0006_authority_envelope.sql');"
   ```

   A later file whose objects are already present uses that same statement with its own filename.

6. When a pending file's objects are absent, apply the files that are still pending:

   ```sh
   wrangler d1 migrations apply DB --remote --config wrangler.test.jsonc
   ```

   That is safe at that point, because the baseline rows mean only the remaining files run. Record every pending file whose objects are already present first, so this command does not try to create them. Read the printed database before you accept the confirmation. If it is `admrn-bridge`, stop. It must be `admrn-bridge-test`. Wrangler runs each still-pending file together with its `d1_migrations` insert. A file that fails is not left recorded. If every remaining file was recorded in the previous step, skip this command.

7. When every pending name has been applied or recorded, list again:

   ```sh
   wrangler d1 migrations list DB --remote --config wrangler.test.jsonc
   ```

   Only this list must print `No migrations to apply!`.

## 4. Deploy, read OWNER_EMAIL back, then claim

Follow [Confirm the owner email](design/owner-lock.md#confirm-the-owner-email) and [Secret lifetime](design/owner-lock.md#secret-lifetime) in this order. The claim writes the deployed `OWNER_EMAIL` into `owner_lock` once. A later deploy does not change that row. The same address again is `owner_locked`. A different address is `owner_mismatch`. A wrong value stays until the owner follows the reset in that design. Read the deployed value back before `BOOTSTRAP_SECRET` exists and before `POST /owner/claim`.

1. Read `OWNER_EMAIL` from `wrangler.test.jsonc` and show the owner that exact string, in full, in the owner's own chat. The read-back is not logged. Wait for an explicit confirmation of that string. If the owner does not confirm it, or the confirmation differs, stop. Leave the secret unset and send no claim.
2. Deploy that private file. This deploy has no `BOOTSTRAP_SECRET`:

   ```sh
   wrangler deploy --config wrangler.test.jsonc
   ```

3. Read `OWNER_EMAIL` from the deployed Worker. The control-plane read is the `plain_text` binding on `GET /accounts/{account_id}/workers/scripts/admrn-bridge-test/settings`. It is not a Worker response, and it is not logged. The script name is `admrn-bridge-test`.
4. If that deployed string is not the exact string the owner confirmed, stop. Put no secret and send no claim.
5. Generate the bootstrap secret only after that match. It is 32 bytes from `crypto.getRandomValues`, base64url without padding: 43 characters from `A-Za-z0-9_-`. A passphrase is not a bootstrap secret. Use one shell for the rest of this section so the path variables stay set. The commands write files outside the clone. They do not print the secret and do not pass it as a Wrangler argument. `umask 077` makes those files mode `0600`. A failed check stops the chain.

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

6. Set the secret from that file. No other deploy comes between the matching read and this command. Wrangler reads stdin and trims trailing whitespace. Run this only after the check above succeeds.

   ```sh
   wrangler secret put BOOTSTRAP_SECRET --config wrangler.test.jsonc < "$secret"
   ```

7. Send one claim. The body is empty. The header file is mode `0600` and is not a curl argument.

   ```sh
   (umask 077; { printf 'Bootstrap-Secret: '; cat "$secret"; printf '\n'; } > "$header")
   curl -sS -D - -o "$HOME/admrn-claim-body" -X POST \
     -H @"$header" \
     "$BRIDGE_ORIGIN/owner/claim"
   ```

   A successful claim is HTTP `201` and a body of `{"locked":true}`. The body has no email and no secret.
8. Delete the local files. Then delete the Worker secret. Do this after every claim attempt, including a non-201, a timeout, or no response.

   ```sh
   rm -f "$secret" "$header"
   wrangler secret delete BOOTSTRAP_SECRET --config wrangler.test.jsonc
   wrangler secret list --config wrangler.test.jsonc
   ```

   The list prints names, not values. `BOOTSTRAP_SECRET` must be absent. Re-read `owner_lock` and `bootstrap_secret_spend` from the primary before any retry. A spend row for the secret just used means stop. Upload a new secret only when `owner_lock` is absent, as [Secret lifetime](design/owner-lock.md#secret-lifetime) requires.

Delete `$HOME/admrn-claim-body` after reading the status. It is not a secret, and it does not belong in the clone.

## 5. Smoke curls before a participant credential

These requests use no credential. In a new shell, read `$BRIDGE_ORIGIN` again with the command in section 1.

```sh
curl -sS "$BRIDGE_ORIGIN/health"
```

Expect `{"ok":true,"service":"admrn-bridge","phase":"v0.1-candidate","status":"v0.1-candidate","mvp":"grok-bot-dot"}`.

```sh
curl -sS "$BRIDGE_ORIGIN/.well-known/oauth-protected-resource/mcp"
curl -sS "$BRIDGE_ORIGIN/.well-known/oauth-authorization-server"
```

The protected-resource document names resource `$BRIDGE_ORIGIN/mcp`, lists that same origin as its only authorization server, and allows the header bearer method. The authorization-server document names that origin as `issuer`, `$BRIDGE_ORIGIN/authorize` as the authorization endpoint, and `$BRIDGE_ORIGIN/token` as the token endpoint. `client_id_metadata_document_supported` is true, S256 is the code challenge method, and there is no `registration_endpoint`.

```sh
curl -sS -D - -o /dev/null -X GET "$BRIDGE_ORIGIN/mcp"
curl -sS -D - -o /tmp/mcp-unauth.json -X POST \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  "$BRIDGE_ORIGIN/mcp"
```

`GET /mcp` is `405`. The POST is `401` with body `{"error":"unauthorized"}`. `WWW-Authenticate` is `Bearer resource_metadata="$BRIDGE_ORIGIN/.well-known/oauth-protected-resource/mcp"`.

## 6. Grok token

Issue the token only after the owner lock exists. The command is [`scripts/grok-credential.mjs`](../scripts/grok-credential.mjs). Its comment names the production database `admrn-bridge`. This instance uses `admrn-bridge-test`. The token file and the SQL file go in a mode `700` directory. The script creates the SQL file mode `600`. The token file is created mode `600` before the token is written.

```sh
secret_dir="$HOME/admrn-test-private"
mkdir -p "$secret_dir"
chmod 700 "$secret_dir"
grok_sql="$secret_dir/grok-credential.sql"
grok_token="$secret_dir/grok-token"
(umask 077
  : > "$grok_token"
  chmod 600 "$grok_token"
  node scripts/grok-credential.mjs issue --out "$grok_sql" > "$grok_token"
) && test "$(wc -c < "$grok_token")" -eq 53 \
  && wrangler d1 execute admrn-bridge-test --remote --config wrangler.test.jsonc --file "$grok_sql" \
  && rm -f "$grok_sql"
```

Stdout is the token plus a newline, so the file is 53 bytes. The SQL file holds the SHA-256 and is mode `0600`. The command does not apply it. The `rm` runs only after the length check and the test-database apply succeed. If the length check fails, delete `$secret_dir/grok-token` and `$secret_dir/grok-credential.sql` and stop. Keep the token file outside the clone until the Grok steps in section 8 are done, then delete it.

Accepted for the MVP: with xAI's API remote MCP tool, xAI's servers make the MCP call, so this bearer passes through xAI's servers on every request. To keep the token on the user's own machine, use Grok Build or custom code that holds the token locally instead of pasting it into a hosted chat.

Authenticated smoke, with the token in a mode-0600 header file rather than a curl argument. In a new shell, read `$BRIDGE_ORIGIN` again with the command in section 1. This block sets `grok_token` from the private directory again. If that read fails or the token is empty, the shell stops. It does not print the token. The header file is created mode `600` before the token is written.

```sh
secret_dir="$HOME/admrn-test-private"
mkdir -p "$secret_dir"
chmod 700 "$secret_dir"
grok_token="$HOME/grok-token"
if [ ! -f "$grok_token" ]; then grok_token="$secret_dir/grok-token"; fi
grok_header="$secret_dir/grok-auth-header"
token_line="$(tr -d '\n' < "$grok_token")" && test -n "$token_line" \
  || { printf '%s\n' "Could not read a Grok token from $HOME/grok-token. Stop." >&2; exit 1; }
(umask 077
  : > "$grok_header"
  chmod 600 "$grok_header"
  printf 'Authorization: Bearer %s\n' "$token_line" > "$grok_header"
)
unset token_line
curl -sS -X POST \
  -H @"$grok_header" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  "$BRIDGE_ORIGIN/mcp"
```

Expect HTTP `200`, `protocolVersion` `2025-06-18`, and `serverInfo.name` `admrn-bridge`. Then `tools/list`:

```sh
grok_header="$HOME/admrn-test-private/grok-auth-header"
curl -sS -X POST \
  -H @"$grok_header" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  --data-binary '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  "$BRIDGE_ORIGIN/mcp"
```

The tool names include `open_item`, `list_items`, `claim_item`, `submit_result`, and `review_result`.

## 7. Connect code and the ChatGPT connector

Add the connector in the owner's own ChatGPT, in the account where Dot runs. Use ChatGPT's custom MCP connector. Build the connector URL from `$BRIDGE_ORIGIN`: the server URL is `$BRIDGE_ORIGIN/mcp`. Do not type the anonymized example. Authentication is OAuth. An API key or a connector with no authentication is the wrong setup.

Start the connection from that ChatGPT. ChatGPT opens `$BRIDGE_ORIGIN/authorize` in the owner's browser. The page says `ChatGPT will connect as Dot` and shows redirect URI `https://chatgpt.com/connector_platform_oauth_redirect`. It shows no email and no item.

One connect from a real Chrome and one from a real Firefox are still required. The repository tests send synthetic `Origin` and `Sec-Fetch-Site` headers. They do not show what a real browser sends on the Connect submit. Run this section once in each browser, each with its own connect code. The second connect revokes the Dot credential from the first. Record the browser, its version, and pass or fail for each in the private notes. A `Connection failed` page with status 403 right after Connect means the browser's site headers were refused. Record that and stop.

Before pasting a code, view the page source and record these in private notes. The notes stay out of the repository and out of chat.

| Field | Where | What to record |
| --- | --- | --- |
| `client_id` | Hidden input `client_id` | The value. The pre-filter accepts only `https://chatgpt.com/oauth/client.json`. Any other value means stop, and do not issue a code. |
| `scope` | Hidden input `scope`, when present | The value, or `absent` when that input is missing. |

Record the MCP version after ChatGPT calls `/mcp`, from the connector UI when it shows the protocol version it sends. The Worker accepts `MCP-Protocol-Version` `2025-06-18` and `2025-03-26`. It does not log that header. Leave `invocation_logs` false. A version ChatGPT does not display is recorded as `not shown`. The smoke request in section 5 used `2025-06-18` from curl, which is separate from ChatGPT's version.

Issue the code only after that page is the tab ChatGPT just opened. [`scripts/connect-code.mjs`](../scripts/connect-code.mjs) prints the code once. The ten minutes start when the SQL file is applied, not when the command runs. Equality at `expires_at` is expired. Apply it to `admrn-bridge-test` immediately, then paste.

```sh
secret_dir="$HOME/admrn-test-private"
mkdir -p "$secret_dir"
chmod 700 "$secret_dir"
code_sql="$secret_dir/connect-code.sql"
code_file="$secret_dir/connect-code"
(umask 077
  : > "$code_file"
  chmod 600 "$code_file"
  node scripts/connect-code.mjs issue --out "$code_sql" > "$code_file"
) && test "$(wc -c < "$code_file")" -eq 44 \
  && wrangler d1 execute admrn-bridge-test --remote --config wrangler.test.jsonc --file "$code_sql"
```

The code file is 43 characters plus the newline stdout adds. If the length check fails, delete both files and stop; the apply did not run. Paste the code only into the connect-code field on that consent tab. Submit. Then delete both files:

```sh
rm -f "$code_sql" "$code_file"
```

The comment inside the generated SQL names the production database `admrn-bridge`. The execute command above names `admrn-bridge-test`. If the consent page was the wrong client, or the code was displayed anywhere other than that tab, expire it instead of pasting:

```sh
secret_dir="$HOME/admrn-test-private"
mkdir -p "$secret_dir"
chmod 700 "$secret_dir"
(umask 077; node scripts/connect-code.mjs expire --out "$secret_dir/connect-code-expire.sql")
wrangler d1 execute admrn-bridge-test --remote --config wrangler.test.jsonc --file "$secret_dir/connect-code-expire.sql"
rm -f "$secret_dir/connect-code-expire.sql" "$secret_dir/connect-code.sql" "$secret_dir/connect-code"
```

`expire` prints nothing. It expires an unused code and a code held by a pending claim. It does not disconnect a Dot that already finished `/authorize`, because a spent code stores the canonical spent record rather than a pending claim. A later successful code does that, because spending a code revokes the previous Dot credential.

After ChatGPT returns from the redirect, ask Dot to call `list_items` with `box` `inbox`. A failure here means stop before the checklist in section 8.

## 8. End-to-end checklist

Use one synthetic item. The text is ordinary test text. Put no token, code, email, or hostname other than what the tools already require into the item. The curls in this checklist use `$BRIDGE_ORIGIN`. In a new shell, read it again with the command in section 1.

Record pass or fail for each step in the private notes, next to the `client_id`, `scope`, and MCP version from section 7.

Pick a new idempotency key for this run. It must match `^req_[A-Za-z0-9_-]{8,64}$`, the same rule as `openItem` in `src/item-lifecycle.ts`. A timestamp or random suffix is enough. This prints one key:

```sh
idempotency_key="req_$(date -u +%Y%m%d%H%M%S)_$(node -e 'process.stdout.write(require("node:crypto").randomBytes(3).toString("hex"))')"
printf '%s\n' "$idempotency_key"
```

Use that same key only to retry this open. A later independent run needs a new key. Reusing a key replays the earlier item, so a later claim can return `execute: false` or the open can come back `deadline_passed`.

`open_item` requires `scope`. Both arrays are required and either may be empty. Omitting `scope` fails the call and writes an `envelope_rejected` audit row. It does not open an item. An empty `allowed_sources` means the `submit_result` in this checklist cites nothing. Put the printed idempotency key in this payload:

```json
{
  "idempotency_key": "<the key printed above>",
  "kind": "task",
  "title": "Test item",
  "body": "Synthetic test item for the bridge test instance.",
  "scope": { "allowed_sources": [], "allowed_resources": [] }
}
```

1. **Dot `open_item`.** In the owner's ChatGPT, have Dot call `open_item` with that payload. ChatGPT may ask the owner to confirm the write. Confirm it in that ChatGPT. The result's `item.id` matches `item_` plus a UUID. The sender is `dot` and the recipient is `grok_bot`. If ChatGPT cannot call the write tool, record that and stop. The server is not changed to allow an unauthenticated call.
2. **Grok `list_items`.** With the header file from section 6, `$HOME/admrn-test-private/grok-auth-header`:

   ```sh
   curl -sS -X POST \
     -H @"$HOME/admrn-test-private/grok-auth-header" \
     -H "Content-Type: application/json" \
     -H "MCP-Protocol-Version: 2025-06-18" \
     --data-binary '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_items","arguments":{"box":"inbox"}}}' \
     "$BRIDGE_ORIGIN/mcp"
   ```

   The inbox includes the new item id.
3. **Grok `claim_item`.** Replace the item id. The first claim returns `execute` true. An `execute` false result means the work was already admitted. Do not perform it again.

   ```sh
   curl -sS -X POST \
     -H @"$HOME/admrn-test-private/grok-auth-header" \
     -H "Content-Type: application/json" \
     -H "MCP-Protocol-Version: 2025-06-18" \
     --data-binary '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"claim_item","arguments":{"item_id":"ITEM_ID"}}}' \
     "$BRIDGE_ORIGIN/mcp"
   ```

4. **Grok `submit_result`.** Same item id. `result` is `Synthetic test result.`

   ```sh
   curl -sS -X POST \
     -H @"$HOME/admrn-test-private/grok-auth-header" \
     -H "Content-Type: application/json" \
     -H "MCP-Protocol-Version: 2025-06-18" \
     --data-binary '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"submit_result","arguments":{"item_id":"ITEM_ID","result":"Synthetic test result."}}}' \
     "$BRIDGE_ORIGIN/mcp"
   ```

   The item state is `submitted`.
5. **Dot accept.** In the same ChatGPT, have Dot call `review_result` with that `item_id` and `decision` `accept`. Leave `checked` unset. The item state is `accepted`.

Delete the Grok token file and header file when the checklist is recorded, and delete them if a later step stops before this point:

```sh
rm -rf "$HOME/admrn-test-private"
rm -f "$HOME/grok-token" "$HOME/grok-auth-header" "$HOME/connect-code" "$HOME/connect-code.sql" "$HOME/admrn-bootstrap-secret" "$HOME/admrn-claim-header"
```

`wrangler secret list --config wrangler.test.jsonc` still must not include `BOOTSTRAP_SECRET`. The private Wrangler file stays uncommitted.
