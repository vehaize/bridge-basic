# Upgrade and recovery

Upgrade, roll back, or stop one operator's own Worker. This is not a schema rollback, and it is not a hosted service. Production install is [docs/install.md](install.md). The test Worker in [docs/test-instance.md](test-instance.md) is a different database. Read `database_name` in the private Wrangler file before every D1 command. Production uses `wrangler.jsonc` and database name `admrn-bridge`. The test instance uses `wrangler.test.jsonc` and `admrn-bridge-test`. The binding in both files is `DB`.

Commands below use `wrangler.jsonc`. On the test instance, use `wrangler.test.jsonc` and stop if the database name is `admrn-bridge`.

No git tag and no GitHub release exist. Do not upgrade by pulling `main`. An upgrade moves from one pinned tag plus its full 40-character SHA to a newer pinned tag plus its SHA, using the [README install rule](../README.md#install). Until a tag is published, there is no published upgrade to run. The procedure below is what to run when that pin exists.

Publishing, restores, and secrets need the owner's approval.

## 1. Backup before an upgrade or a restore

Record a D1 Time Travel bookmark, then export a SQL copy. Both are remote reads. The export contains the operator's rows. Write it outside the clone and do not commit it.

```sh
wrangler d1 time-travel info DB --config wrangler.jsonc
wrangler d1 export DB --remote --config wrangler.jsonc --output "$HOME/admrn-bridge-backup.sql"
```

`time-travel info` prints the current bookmark. Keep that bookmark with the date and the git SHA you are leaving (`git rev-parse HEAD`). D1 Time Travel keeps history for 30 days on Workers Paid and 7 days on Workers Free. `time-travel info --timestamp <RFC3339>` prints the bookmark at an earlier point inside the applicable window.

The export is a copy you can read. It is not a migration. Do not pass it to `wrangler d1 migrations apply`. Putting the database back is Time Travel, in section 4. That section deletes `BOOTSTRAP_SECRET`, waits until no claim is in flight, sets `LIVE_ENABLED` to `false`, and disables the custom domain before it records the current bookmark and restores. It leaves the domain disabled until credential revocations are back, then enables the domain, turns writes on, and only then does a fresh owner bootstrap. A restore while that secret is still deployed, while a claim is in flight, or while the custom domain is still serving, can remove `owner_lock` and rewind `bootstrap_secret_spend`, and can serve a credential the bookmark brings back. The secret still on the Worker can then claim the restored database.

Also record the Worker versions:

```sh
wrangler deployments list --config wrangler.jsonc
wrangler deployments status --config wrangler.jsonc
```

`deployments list` shows the ten most recent Worker versions. It does not show a git SHA. `GET /health` does not either.

## 2. Upgrade

Check out the new pinned SHA and prove it, as [docs/install.md](install.md) section 1 describes. Run `npm ci`, `npm run lint`, `npm test`, and `npm run build` on that checkout.

See whether `migrations/` has files the database has not recorded:

```sh
wrangler d1 migrations list DB --remote --config wrangler.jsonc
```

`No migrations to apply!` means the schema tracking matches this checkout. A table of filenames means those files are pending.

Apply pending migrations before deploying code that needs them:

```sh
wrangler d1 migrations apply DB --remote --config wrangler.jsonc
wrangler d1 migrations list DB --remote --config wrangler.jsonc
```

The second list must print `No migrations to apply!`. The command asks for confirmation in a terminal. Read the database it names before accepting. Do not apply `migrations/*.sql` with `wrangler d1 execute --file`. That leaves `d1_migrations` short, and the next `migrations apply` tries to create objects that already exist. If a previous database was loaded that way, reconcile the rows as [docs/install.md](install.md) section 4 describes, after you have confirmed the objects exist. Do not insert a filename whose objects are missing.

Then deploy that same checkout:

```sh
wrangler deploy --config wrangler.jsonc
```

Verify:

1. `wrangler d1 migrations list DB --remote --config wrangler.jsonc` prints `No migrations to apply!`.
2. `curl -sS "$BRIDGE_ORIGIN/health"` returns the static JSON (`ok`, `service`, `phase`, `status`, `mvp`). It must not be read as a build SHA.
3. `wrangler deployments list --config wrangler.jsonc` shows the deployment you just created. `wrangler deployments status --config wrangler.jsonc` shows that version as current.
4. A credentialed `tools/list` still returns the item tools. Use the operator's existing Grok bearer or Dot session. Do not print the bearer.

Deploying code that reads `item.delivered_at` before `0005_item_receipt.sql` is applied makes item tools fail closed. The tool result is `internal_error`. The log reason is `receipt_column_absent`. `GET /health` still returns 200. Apply the migration, then deploy.

`migrations apply` is the only schema path. Generated Grok and Dot SQL stays on `wrangler d1 execute --file` and is not copied into `migrations/`.

This upgrade does not restore D1. A restore is section 4. That section removes `BOOTSTRAP_SECRET`, finishes in-flight claims, sets `LIVE_ENABLED` to `false`, and disables the custom domain before restoring. Writes stay off until the domain is enabled again and the var is the exact string `true` or unset.

## 3. Roll back the Worker

Worker rollback is not schema rollback. It does not run a down migration. This repository has no down files.

Roll back to a previous Worker version:

```sh
wrangler deployments list --config wrangler.jsonc
wrangler rollback <version-id> --config wrangler.jsonc
```

Omit `<version-id>` and Wrangler asks which listed version to restore. Or check out the previous pinned tag, prove the SHA, and `wrangler deploy --config wrangler.jsonc` from that checkout. Either path publishes Worker code. Neither path drops a column, deletes a row, or rewrites `d1_migrations`.

After a Worker rollback, list migrations again. The files on the old checkout and the rows in `d1_migrations` can disagree when the old checkout does not contain a file the database already recorded. Do not delete `d1_migrations` rows to force a match. Do not re-apply a file whose objects are already present.

### Per-migration notes

Every file in `migrations/` is forward only.

| File | What it leaves behind after a Worker rollback |
| --- | --- |
| `0001_owner_lock.sql` | `owner_lock` and `bootstrap_secret_spend` stay. A Worker rollback does not clear the owner. Reset is the procedure in [owner-lock.md](design/owner-lock.md#reset), which deletes the owner row only after `BOOTSTRAP_SECRET` is gone and the claim route is not being served. |
| `0002_item_lifecycle.sql` | The `item` table and its indexes stay. Items stay. |
| `0003_participant_credentials.sql` | `participant` and `participant_credential` stay, including the seeded `grok_bot` and `dot` rows and any bearer or grant rows. |
| `0004_connect_code.sql` | `connect_code` stays. Unused codes stay until they expire or are marked used. |
| `0005_item_receipt.sql` | `item.delivered_at` stays. The column is nullable. Rolling back the Worker does not remove it. A build that reads items and finds the column absent fails closed with log reason `receipt_column_absent`. |
| `0006_authority_envelope.sql` | The rebuilt `item` table stays. It is `WITHOUT ROWID`, keeps every earlier column and row and its four indexes, and adds the nullable `envelope_json` and `envelope_sha256`. Rows from before 0006 keep null envelopes. The triggers `item_envelope_immutable`, `item_no_replace`, and `item_no_replace_update` stay, so an update of either envelope column fails. `item_audit` and `item_audit_head` stay with their triggers. An audit row cannot be updated, and cannot be deleted until it is more than 90 days old. A Worker rollback does not undo the rebuild or remove audit rows. Applying the file again stops at its first statement and changes nothing. Recovery from 0006 is a forward fix, or a Time Travel restore (section 4) to a bookmark from before it was applied. |
| `0008_refresh_token_family.sql` | `oauth_refresh_family`, `oauth_refresh_token`, their index, family/credential revocation synchronization triggers, and the guard against clearing family revocation stay. Family state, token-hash history, pending claims, and in-place `revoked_at` values survive Worker rollback. The file is idempotent; no down migration is provided. |

Migration `0008_refresh_token_family.sql` adds OAuth refresh-family storage and
leaves released migrations 0001-0007 unchanged. Do not drop those objects,
clear family state, or remove migration-tracking rows during rollback. Older
code does not enforce the family policy; rolling back can restore unbounded
previous-token reuse inside the provider grant lifetime. Prefer a forward fix
with OAuth traffic quiesced. See [OAuth behavior and limits](v0.1-oauth-limitations.md).
Applying 0008 to an operator database and deploying compatible code require an
authorized rollout, with the migration applied before code that reads it.
That rollout decision must also account for pre-F4 grants: enrollment records
only the first validated token and later successors, not unknown hashes of
older ancestors. A pending claim left by a crash has no automatic takeover;
owner revocation and reconnect provide recovery. Re-enabling a participant does
not repair an abandoned claim.

Refreshes performed by a Worker without family enforcement can advance provider
state without updating D1 history. After rolling forward, an unrecorded but
provider-valid refresh token receives `400 invalid_grant` when its family has
no pending claim. Revoke affected OAuth credentials and reconnect. Do not clear
family history or reset pending claims to attempt recovery rotations.

`oauth_refresh_family.credential_id` references `participant_credential(id)`
with the default `NO ACTION` on delete. A future credential-table rebuild must
handle those foreign-key references and recreate `oauth_credential_revoke_family`,
which is attached to `participant_credential`. A rebuild patterned after 0007
must account for these later objects before dropping or replacing that table.

0001 through 0005 only add objects. 0006 is not additive. It copies `item` into a new table, drops the old table, and renames the copy. Its triggers also change what a write does: an `ON CONFLICT ... DO NOTHING` insert that repeats an existing `sender` and `idempotency_key` aborts in `item_no_replace` instead of doing nothing. The Worker in this checkout catches that abort and reads the first row again.

On a database that stops at 0005, an older Worker that does not mention `delivered_at` can still use the earlier columns. That is not a promise about a future migration. No test runs a Worker built before 0006 against a 0006 database. `test/migration-0006.test.ts` checks the schema only: the earlier columns keep their values, a plain state update and an item delete still succeed, and an update of either envelope column fails. Items such a Worker opens get null envelope columns unless that build writes them. Whether it writes `item_audit` rows also depends on that build. Once a Worker from this checkout is deployed again, it refuses a row with null envelope columns, whether the row predates 0006 or an older Worker opened it. A read returns `envelope_rejected`, or `rate_limited` past the daily rejection cap. Claim and submit return `missing_envelope`. A list shows only a stub with no title and `envelope_status` `rejected`. Cancel and review still work on such a row, and retention still expires and deletes it.

There is no tested matrix of every older SHA against a migrated database. If the rolled-back Worker errors, recovery is a forward fix on a new checkout, or the Time Travel restore in section 4. It is not a down file. Follow that section's order: remove `BOOTSTRAP_SECRET`, finish in-flight claims, set `LIVE_ENABLED` to `false`, and disable the custom domain before the restore. Leave the domain disabled until the restored revocations are verified, then enable the domain, turn writes back on, and only then start a fresh owner bootstrap. A Worker rollback leaves `owner_lock` and `bootstrap_secret_spend` where they are. A restore can remove the owner row, rewind the spend table, and bring a revoked credential back.

A forward fix is a later migration file in a future pinned checkout, applied with `wrangler d1 migrations apply` before the code that needs it. This repository does not add that file from the recovery steps.

## 4. Time Travel restore

Time Travel restores the whole D1 database to a bookmark, or to a timestamp inside the applicable window: 30 days on Workers Paid and 7 days on Workers Free. Secrets stay on the Worker. Stop owner claims before the bookmark you are leaving and before the restore. A restore that runs while `BOOTSTRAP_SECRET` is still deployed, or while a claim is in flight, can remove `owner_lock` and rewind `bootstrap_secret_spend`, and that still-valid secret can claim the restored database.

A bookmark taken before a credential was revoked brings that credential back. Leave the custom domain disabled from before the restore until that revocation is on the restored database again. A deploy of the normal `routes` entry, with that custom domain still enabled, serves the restored credential until the cleanup below has run.

What the restore loses, and what it does not touch:

- Every D1 write after the bookmark is gone. That includes items, credential rows, connect codes, `owner_lock`, `bootstrap_secret_spend`, and `d1_migrations` rows inserted after the bookmark.
- A restore can bring back revoked credentials, unused connect codes, and items that were already claimed.
- KV is not restored. `OAUTH_KV` can still hold Dot grant records that no longer match D1.
- The Worker version is not restored. Secrets are not restored. `BOOTSTRAP_SECRET` and `WAKE_SECRET_GROK_BOT` stay as they are on the current deployment.
- A timestamp older than the applicable window is outside the window this command accepts. The SQL export from section 1 is the copy you still have. This guide does not load that file as a migration.

1. Stop owner claims. Remove `BOOTSTRAP_SECRET`. Wrangler 4.151.1 accepts `wrangler secret delete <key>` and the global `--config` flag. The delete deploys a new version immediately. Then `wrangler secret list` must not include that name. The list prints names, not values. A request already running keeps the secret and `OWNER_EMAIL` it started with, so wait until no claim is in flight. Do not restore on the strength of the secret list alone. This delete leaves the custom domain attached. The following steps turn writes off and disable that domain before any D1 change, as [Secret lifetime](design/owner-lock.md#secret-lifetime) describes.

   ```sh
   wrangler secret delete BOOTSTRAP_SECRET --config wrangler.jsonc
   wrangler secret list --config wrangler.jsonc
   ```

2. Set `LIVE_ENABLED` to `false` in the private `wrangler.jsonc`. Do not deploy this edit on its own. `src/router.ts` refuses the request when `consultsLiveSwitch` is true and `liveWritesEnabled(env.LIVE_ENABLED)` is false. `liveWritesEnabled` returns true only when the value is unset (`undefined`) or the exact string `true`. Every other value is off, including an empty string, `false`, `FALSE`, `TRUE`, `0`, `1`, `yes`, and a string with surrounding space. The routes that consult the gate are `POST /owner/claim`, `POST /authorize`, and `/token` except a refresh-token grant. `GET /health` does not read the var. An existing deploy that does not set the var keeps writes on, so `POST /owner/claim` and `POST /authorize` still run until the deploy in the next step. The example Wrangler file does not set the key. The var does not remove `BOOTSTRAP_SECRET`. The gate is `liveWritesEnabled` in `src/live-switch.ts`; this paragraph describes its behavior.

   Keep `OWNER_EMAIL` and `BRIDGE_ORIGIN` in that same `vars` object.

   ```jsonc
   "vars": {
     "LIVE_ENABLED": "false"
   }
   ```

3. Shut down public access, then deploy once. The default install is `workers.dev`. A custom domain is the optional path. Follow the branch that matches the private file.

   Default `workers.dev` install. Set `workers_dev` to false and `preview_urls` to false, then deploy. [`workers.dev`](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/) documents this disable. The dashboard path on that page is Workers & Pages, select the Worker, Settings > Domains & Routes, and on `workers.dev` click Disable, then confirm. [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) names the keys `workers_dev` and `preview_urls`. Disabling the `workers.dev` route does not disable Version URLs or Preview URLs, so the same file sets `preview_urls` to false. This repository already keeps `preview_urls` false. A dashboard disable that leaves `workers_dev` unset or true is turned back on at the next Wrangler deploy, so this deploy is the shutdown that holds. Leave `LIVE_ENABLED` set to `false`. Do not pass `--keep-vars`, `--routes`, or `--domains`.

   ```jsonc
   "workers_dev": false,
   "preview_urls": false
   ```

   ```sh
   wrangler deploy --config wrangler.jsonc
   ```

   The public hostname must not return the Worker's static health JSON (`ok`, `service`, `phase`, `status`, `mvp`). If it does, the `workers.dev` hostname is still serving. Stop, and do not restore. Leave `workers_dev` false through the restore and the cleanup below. Wait until no request that started before this deploy is still running.

   Optional custom domain.

   Disable the custom domain in that same private file, then deploy once. Wrangler 4.151.1 `wrangler deploy --help` lists `--routes` / `--route` as routes to upload and `--domains` / `--domain` as custom domains to deploy to. Both require a value, so neither flag can be passed empty to clear a hostname. Do not detach by deleting the `routes` array. This Wrangler publishes custom domains only when the list it deploys is non-empty, so `"routes": []` leaves a custom domain that is already attached. Do not pass `--routes` or `--domains` on this deploy. `--routes` replaces the routes from the config, and `--domains` adds custom domains on top of them.

   On the existing custom-domain object (`custom_domain` true, the hostname in `pattern`), set `enabled` to false and `previews_enabled` to false. `enabled` false stops production traffic on that hostname. `previews_enabled` false stops preview hostnames on that domain. Leave `workers_dev` false and `preview_urls` false, so a `workers.dev` name is not a second path. Leave `LIVE_ENABLED` set to `false`. Do not pass `--keep-vars`. Wrangler 4.151.1 `deploy --help` says that without that flag, Wrangler deletes all vars before setting the vars in the config, so this file has to keep `OWNER_EMAIL`, `BRIDGE_ORIGIN`, and `LIVE_ENABLED` set to `false`. The deploy output names that hostname as a custom domain and includes `disabled`.

   ```jsonc
   "workers_dev": false,
   "preview_urls": false,
   "routes": [
     {
       "pattern": "<YOUR_DOMAIN>",
       "custom_domain": true,
       "enabled": false,
       "previews_enabled": false
     }
   ]
   ```

   ```sh
   wrangler deploy --config wrangler.jsonc
   ```

   The public hostname must not return the Worker's static health JSON (`ok`, `service`, `phase`, `status`, `mvp`). If it does, the custom domain is still serving. Stop, and do not restore. Leave the domain disabled through the restore and the cleanup below. Wait until no request that started before this deploy is still running.

4. Take the current bookmark, then restore. `time-travel info` prints the bookmark of the database after claims have stopped and the custom domain is disabled. Keep that bookmark with the date. It is the point you are leaving. Restore to the bookmark you mean to return to: the one recorded in section 1, or the one `time-travel info --timestamp <RFC3339>` prints for an earlier point inside the applicable window. Wrangler 4.151.1 accepts `wrangler d1 time-travel info <database>` and `wrangler d1 time-travel restore <database> --bookmark <bookmark>`. The remote flag is not valid on either command.

   ```sh
   wrangler d1 time-travel info DB --config wrangler.jsonc
   wrangler d1 time-travel restore DB --bookmark <bookmark> --config wrangler.jsonc
   ```

5. Verify the restored database before anything else writes, and before the custom domain is enabled again. Read `owner_lock` and `bootstrap_secret_spend` from the primary. The rows must be the rows that bookmark held. An empty `owner_lock` is the expected state when the bookmark predates the claim. Spend rows written after the bookmark are gone. These reads omit `owner_email` and `secret_sha256`.

   ```sh
   wrangler d1 execute DB --remote --config wrangler.jsonc --command "SELECT id, claimed_at, claim_source FROM owner_lock;"
   wrangler d1 execute DB --remote --config wrangler.jsonc --command "SELECT spent_at FROM bootstrap_secret_spend;"
   ```

   On the restored database, with `BOOTSTRAP_SECRET` still absent and the custom domain still disabled:

   - Revoke every credential row. `scripts/grok-credential.mjs revoke` covers `grok_bot` bearers only. A restored Dot row is `oauth_grant`. Set `revoked_at` on every credential row that does not have it. The statement does not print a hash.
   - Mark every unused connect code used.
   - Mark every restored `open` or `claimed` item `expired`, so a claim does not run twice.

   ```sh
   wrangler d1 execute DB --remote --config wrangler.jsonc --command "UPDATE participant_credential SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE revoked_at IS NULL;"
   wrangler d1 execute DB --remote --config wrangler.jsonc --command "SELECT count(*) AS active_credentials FROM participant_credential WHERE revoked_at IS NULL;"
   ```

   `active_credentials` must be `0`. Do not select `token_sha256` or `connect_code_sha256`. If the count is not `0`, stop. Do not enable the custom domain.

   Settle the owner lock with the reset rules in [owner-lock.md](design/owner-lock.md#reset) before issuing a new Grok bearer or a new Dot connect code. Those new files are credential SQL applied with `wrangler d1 execute --file`, not schema migrations. `wrangler d1 migrations list DB --remote --config wrangler.jsonc` must print `No migrations to apply!` for the checkout you are running. If the bookmark predates a migration the checkout contains, list shows that file as pending. Apply it only when its objects are actually absent.

6. Restore public access on the hostname this install uses. Follow one branch. Keep `LIVE_ENABLED` at `false`. Deploy with no `--keep-vars`, no `--routes`, and no `--domains`.

   Default `workers.dev` install. Set `workers_dev` to true and keep `preview_urls` false, then deploy. [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) names `workers_dev`. `true` runs the Worker on the `workers.dev` subdomain. [`workers.dev`](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/) is the page for that route. Keep `preview_urls` false. That is the install default, and disabling the `workers.dev` route does not disable Preview URLs.

   ```jsonc
   "workers_dev": true,
   "preview_urls": false
   ```

   ```sh
   wrangler deploy --config wrangler.jsonc
   curl -sS "$BRIDGE_ORIGIN/health"
   ```

   `GET /health` returns the static JSON (`ok`, `service`, `phase`, `status`, `mvp`). That request does not read `LIVE_ENABLED`. A 200 does not mean writes are on. `POST /owner/claim` and `POST /authorize` still return `403` and `{"error":"live_disabled"}` while the var is `false`.

   Optional custom domain.

   Enable the custom domain again. Keep `LIVE_ENABLED` at `false`, `workers_dev` false, `preview_urls` false, and `previews_enabled` false. Set `enabled` back to true. Deploy that file with no `--keep-vars`, no `--routes`, and no `--domains`.

   ```jsonc
   "routes": [
     {
       "pattern": "<YOUR_DOMAIN>",
       "custom_domain": true,
       "enabled": true,
       "previews_enabled": false
     }
   ]
   ```

   ```sh
   wrangler deploy --config wrangler.jsonc
   curl -sS "$BRIDGE_ORIGIN/health"
   ```

   `GET /health` returns the static JSON (`ok`, `service`, `phase`, `status`, `mvp`). That request does not read `LIVE_ENABLED`. A 200 does not mean writes are on. `POST /owner/claim` and `POST /authorize` still return `403` and `{"error":"live_disabled"}` while the var is `false`.

7. Turn writes back on, then prove the gate is open. Do this before step 8. `src/router.ts` passes `POST /owner/claim` and `POST /authorize` through the write gate only when `env.LIVE_ENABLED` is unset or the exact string `true`. Set the var to that exact string, or remove the key. Deploy with `wrangler deploy --config wrangler.jsonc` and do not pass `--keep-vars`. Without `--keep-vars`, Wrangler deletes vars that are not in the file, so a removed key is unset and the gate treats it as on. With `--keep-vars`, a removed key stays `false` and `POST /owner/claim` stays refused. Secrets are not deleted by this deploy. Leave the custom domain enabled.

   ```jsonc
   "vars": {
     "LIVE_ENABLED": "true"
   }
   ```

   ```sh
   wrangler deploy --config wrangler.jsonc
   curl -sS -D - -o "$HOME/admrn-claim-body" -X POST "$BRIDGE_ORIGIN/owner/claim"
   ```

   Send no `Bootstrap-Secret`, no `Origin`, and no `Sec-Fetch-Site`. The gate is open when the status is `401` and the body is `{"error":"bootstrap_secret_required"}`. That request writes nothing: the claim handler returns before it reads D1. Status `403` and `{"error":"live_disabled"}` means the gate is still shut. `GET /health` does not make this check. Delete `$HOME/admrn-claim-body` after reading it. The same gate refuses `POST /authorize`, so a new Dot authorization waits on this result.

   `POST /owner/claim` checks the site strictly. While `LIVE_ENABLED` is off,
   it returns 403 `live_disabled` regardless of the site headers. Otherwise,
   a supplied `Origin` must exactly match canonical `BRIDGE_ORIGIN`: HTTPS,
   lowercase host, no port, path, or trailing slash. If that configuration is
   unset or noncanonical, every supplied `Origin` is refused. Literal
   `Origin: null` is always refused, unlike the consent form on `POST /authorize`.
   With `Origin` absent, `Sec-Fetch-Site` must be absent or exactly `same-origin`.
   A site refusal returns 403 `cross_site`.

8. Set a new `BOOTSTRAP_SECRET` only when a fresh owner bootstrap is truly intended: you are about to claim once, and the restored `owner_lock` is absent or is not the owner row to keep. Generate that new secret as [docs/install.md](install.md) section 5 describes, after [Confirm the owner email](design/owner-lock.md#confirm-the-owner-email). Never upload the `BOOTSTRAP_SECRET` value deleted in step 1. When the restored owner row is the one to keep, leave `BOOTSTRAP_SECRET` absent. The custom domain is already enabled.

## 5. Emergency stop

There is no route that disables the Worker. The participant stop is `participant.enabled`. `LIVE_ENABLED` is the write gate. Only an unset value or the exact string `true` leaves writes on. Section 4 sets that var to `false` and disables the custom domain before a Time Travel restore. It sets the var back to `true`, or unsets it, only after that domain is enabled again and before a fresh owner bootstrap.

`0003_participant_credentials.sql` seeds `grok_bot` and `dot` with `enabled = 1`;
0007 adds `claude`. Setting `enabled` to `0` stops later requests that present
that participant's credential. An otherwise valid credential receives temporary
503 with `Retry-After: 60` on `/mcp`; Dot and Claude receive the same response on
`/token`. OAuth grants and families are preserved, and re-enable lets the same
refresh token continue without a reconnect. Grok's existing bearer also resumes
without replacement. A rotation admitted before the pause may still finish and
return its successor; the next request observes the pause. The other
participants are unchanged. Stored items and credential rows stay. This is not
revocation. Revocation sets `revoked_at` in place on
`participant_credential`; it is not append-only. OAuth family reuse revocation
also marks the family revoked, and D1 refuses access and refresh on the next
request. Do not use a reconnect as a disable/re-enable continuity check.

Stop only the intended participant. The examples below name Grok Bot and Dot;
for Claude, use the exact id `claude` in its separately authorized statement.
Read the statement before running it and run only the intended line.

```sh
wrangler d1 execute DB --remote --config wrangler.jsonc --command "UPDATE participant SET enabled = 0 WHERE id = 'grok_bot';"
wrangler d1 execute DB --remote --config wrangler.jsonc --command "UPDATE participant SET enabled = 0 WHERE id = 'dot';"
```

Allow a participant again with `enabled = 1` and the same `id`. Confirm with a read that returns the two ids and their `enabled` values, and does not return emails, token hashes, or codes:

```sh
wrangler d1 execute DB --remote --config wrangler.jsonc --command "SELECT id, enabled FROM participant;"
```

To stop new owner claims during a reset, remove the route so `POST /owner/claim` receives nothing new, as [Secret lifetime](design/owner-lock.md#secret-lifetime) describes. That is separate from `participant.enabled`. `wrangler secret delete BOOTSTRAP_SECRET` removes the claim secret. It does not stop Grok Bot or Dot. `participant.enabled` does not remove `BOOTSTRAP_SECRET` and does not stop `POST /owner/claim`. A Time Travel restore still starts at section 4. That section deletes `BOOTSTRAP_SECRET`, waits until no claim is in flight, sets `LIVE_ENABLED` to `false`, and disables the custom domain before it records the bookmark and restores. The domain stays disabled until the restored credential rows are revoked again.

`GET /health` keeps returning its static JSON while a participant is disabled. It is not a measure of whether Grok Bot or Dot can call `/mcp`.
