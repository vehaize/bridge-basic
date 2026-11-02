# ADMRN Bridge

**Status: v0.1.0-rc.1 candidate for supervised fresh-install evaluation**

ADMRN Bridge is a single-tenant bridge between **Grok Bot**, **Dot (ChatGPT)**, and **Claude (claude.ai)**. You deploy it yourself, to your own Cloudflare account, as a Worker with D1. This repository does not host a multi-tenant service.

ADMRN Bridge is an independent project and is not an xAI product.

Documentation lives at [admrn.com](https://admrn.com). This repository does not contain a docs site.

This repository is the Basic package. Grok Bot, Dot, and Claude share the item lifecycle. Basic has no licence key, entitlement, paywall, feature gate, or engineering executor. The participant templates below are operator instructions, not Workers.

`GET /health` is unauthenticated and returns the phase status, not a build version, an environment name, the owner email, or any binding data. Its legacy `mvp: grok-bot-dot` value is retained for compatibility. `POST /owner/claim` locks the owner email once and needs the one-time bootstrap secret. See [docs/design/owner-lock.md](docs/design/owner-lock.md).

Dot and Claude connect with OAuth. `GET /authorize` shows the consent page. `POST /authorize` spends a one-time connect code from the form body. `POST /token` exchanges an authorization code and refreshes a token. `GET /.well-known/oauth-authorization-server` and `GET /.well-known/oauth-protected-resource/mcp` publish the metadata. These routes require `BRIDGE_ORIGIN` to be the request's https origin. `/authorize` and `/token` also require `OAUTH_KV`. Only the fixed ChatGPT and claude.ai clients are accepted, and the owner lock has to exist before a code can be spent.

Writes stay on only when `LIVE_ENABLED` is unset or the exact string `true`. Every other value is off (fail closed). Off refuses `POST /owner/claim`, `POST /authorize`, and `/token` except `grant_type=refresh_token`, with reason `live_disabled`. A refresh still runs so a client can replace the 3600-second access token and keep reading. A browser `POST /authorize` gets a small HTML page at status 403; other clients get JSON. `list_items`, `get_item`, `initialize`, `ping`, `tools/list`, and `notifications/initialized` keep working. Every other registered tool returns the tool error `live_disabled`. The daily retention cron still expires items and purges finished rows when writes are off. See [upgrade and recovery](docs/upgrade-and-recovery.md).

`POST /mcp` is the item lifecycle for `grok_bot`, `dot`, and `claude`. Grok Bot sends a bearer credential. Dot and Claude send their respective OAuth access tokens. A missing, invalid, or revoked credential stops before any item is read or changed. An OAuth token is accepted only when its scope equals the scope stored for that grant. Each participant can open an item for either of the others with `recipient`. Omission preserves the Dot/Grok defaults; Claude must name a recipient. All seven item tools are shared, and an uninvolved third participant cannot access the item. The recipient can claim it and submit one result. The sender can accept or reject that result, and can cancel an open or claimed item before the deadline. Cancellation does not send a remote signal. An open or claimed item past its deadline is expired. `deadline_minutes` is an integer from 5 to 1440 and defaults to 360. An item is a task, question, or proposal. Item text is untrusted data and grants no authority. The lifecycle does not run the work.

`npm run grok-credential` writes SQL to issue or revoke the Grok Bot bearer. Issuing revokes any active bearer and inserts the new one. `npm run connect-code` writes SQL to issue or expire connect codes with `--participant dot|claude` (default: `dot`). Reconnection revokes only that participant’s previous credential. An issued code expires ten minutes after that file is applied. `expire` also expires a code that is only held by a pending claim. It does not expire a code that `/authorize` has already spent. Issuing either one uses the current owner lock. Neither command applies the file or calls Cloudflare. Any other path returns 404.

The [Claude Basic design](docs/design/claude-basic-participant.md) and
[installation guide](docs/install.md) describe the fixed OAuth
identities and migration `0007_claude_basic_participant.sql`. Existing migrations
are unchanged. No operator database migration or live onboarding is performed by this change.
Operator instruction templates: [Grok Bot](templates/grok-bot/),
[Dot](templates/dot/), and [Claude](templates/claude/).

The v0.1 release requires migration `0008_refresh_token_family.sql` and its matching Worker: D1 tracks each refresh-token family, with one use of the immediately previous token during an approximately 60-second grace period. Owner/family revocation updates `revoked_at` in place and blocks refresh and existing access tokens on their next request. A disabled participant receives temporary HTTP 503 with `Retry-After: 60` and keeps its grant; enabling it resumes the same client.

## Install

Install a pinned release only. A pin is a git tag plus the full 40-character commit SHA published with that release. Do not install from `main`, a branch tip, or a tag you have not checked.

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

`npm ci` installs the lockfile and checks each dependency's integrity hash. Do not use `npm install` for a release checkout.

Release signatures are not available yet. [docs/release-signing.md](docs/release-signing.md) is the plan. No signing key is in this repository. Do not create one. A missing signature is not a reason to skip the SHA check.

### What a bot may do without the owner

- Read this repository and the docs it links.
- Fetch a pinned tag and check out its commit only after the SHA matches.
- Run `npm ci`, `npm run lint`, `npm test`, and `npm run build`.
- Copy [`wrangler.example.jsonc`](wrangler.example.jsonc) to a gitignored `wrangler.jsonc` and leave every placeholder unchanged.

### What needs the owner's approval

The bot stops until the owner explicitly approves each item:

- Keys. Cloudflare API tokens, Wrangler secrets, `.dev.vars`, OAuth secrets, and any other credential.
- Permissions. Cloudflare account access, Worker routes, DNS, GitHub permissions, and making this repository public.
- Payments. Billing changes, paid plans, and any purchase. Basic has no licence key or paywall. Paying is still the owner's decision.
- Publishing. `wrangler deploy`, `git push`, tags, releases, pull requests, `npm publish`, and posting the source in public.

A bot does not guess an approval. It does not store a secret in the repository, a log, or a chat transcript.

## Deploy model

One operator, one Cloudflare account. These steps publish a Worker. A bot does not run them unless the owner has approved publishing:

1. Copy [`wrangler.example.jsonc`](wrangler.example.jsonc) to `wrangler.jsonc`. That copy is gitignored. The example sets `enable_request_signal`, which aborts `request.signal` when the client disconnects so a Connect submit can clear its pending claim. Without that flag, disconnect cleanup does not run. The 10-second claim lease still releases the code.
2. Replace every placeholder in [`wrangler.example.jsonc`](wrangler.example.jsonc): `<YOUR_ACCOUNT_ID>`, `<YOUR_D1_DATABASE_ID>`, `<YOUR_KV_NAMESPACE_ID>`, `<YOUR_OAUTH_KV_NAMESPACE_ID>`, `<YOUR_DOMAIN>`, `<OWNER_EMAIL>`, `<YOUR_TEST_D1_DATABASE_ID>`, `<YOUR_TEST_KV_NAMESPACE_ID>`, and `<YOUR_TEST_OAUTH_KV_NAMESPACE_ID>`. Replace the rate-limit `namespace_id` values `1001` and `1002` with two different strings, each a positive integer unique to the account. A descriptive name is not a `namespace_id`. A KV namespace id is a hex id Cloudflare issues. Leave the commented `env.test` block commented on a production file. A missing `UNAUTHENTICATED_RATE_LIMIT` or `AUTHENTICATED_RATE_LIMIT` binding makes a charged request return 503 `rate_limit_unavailable`.
3. Create the D1 database and the KV namespaces in your account. Apply schema files only with `wrangler d1 migrations apply DB --remote --config wrangler.jsonc`. That command records each file in `d1_migrations`. Do not apply `migrations/*.sql` with `wrangler d1 execute --file`. Then deploy with Wrangler from your machine.
4. Claim the owner as [docs/install.md](docs/install.md) and [docs/design/owner-lock.md](docs/design/owner-lock.md) describe. Each step there that sets a secret or deploys needs the owner's approval.

The production procedure, including every placeholder, the secret names, and how to read the deployed Worker version, is [docs/install.md](docs/install.md). Upgrade, rollback, and emergency stop are [docs/upgrade-and-recovery.md](docs/upgrade-and-recovery.md). [docs/test-instance.md](docs/test-instance.md) is a different Worker. It is not this install.

Continuous integration runs a funding-metadata check, lint, test, and build. It does not deploy and it does not use secrets.

## Develop

Requires Node.js `^22.13.0 || >=24`. CI installs `>=22.13.0 <23`. `npm test` uses `--experimental-strip-types`, which Node.js added in 22.6.0.

```sh
npm ci
npm run lint
npm test
npm run build
```

`npm ci` and `npm install` remove `funding` entries from `package-lock.json` when they finish. `npm run lint` and `npm run build` regenerate `worker-configuration.d.ts` from the example Wrangler config. That file is gitignored. Do not hand-write an `Env` interface.

## License

[AGPL-3.0-only](LICENSE). Copyright (C) 2026 ADMRN (admrn.com). See [COPYRIGHT](COPYRIGHT).

The AGPL source offer applies once this repository goes public. Going public needs the repository owner.

What is on `main` is summarised in [CHANGELOG.md](CHANGELOG.md). That file is not a release. There is no git tag.

Contributions are made by pull request and require a [Developer Certificate of Origin](https://developercertificate.org/) sign-off. See [CONTRIBUTING.md](CONTRIBUTING.md).

From v0.1.0, contributions require a Developer Certificate of Origin sign-off (`Signed-off-by`).
