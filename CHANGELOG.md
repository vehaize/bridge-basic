# Changelog

All notable changes to ADMRN Bridge are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project has no release. Semantic versions below a heading are candidate names, not tags.

## [Unreleased]

No git tag and no GitHub release exist. `package.json` version is `0.0.0`. The notes under the candidate heading describe what is merged on `main`. They are not a release, and they do not promise later work.

The v0.1 release requires migration `0008_refresh_token_family.sql` and its matching Worker: D1 tracks each refresh-token family, with one use of the immediately previous token during an approximately 60-second grace period. Owner/family revocation updates `revoked_at` in place and blocks refresh and existing access tokens on their next request. A disabled participant receives temporary HTTP 503 with `Retry-After: 60` and keeps its grant; enabling it resumes the same client.

### v0.1.0 candidate

#### Added

- A single-tenant Worker the operator deploys to their own Cloudflare account, with D1. `GET /health` returns a static status and no build SHA. `POST /owner/claim` locks `OWNER_EMAIL` once with the one-time secret `BOOTSTRAP_SECRET` (migrations `0001_owner_lock.sql`).
- The Grok Bot and Dot item lifecycle (migration `0002_item_lifecycle.sql`). Tools on `POST /mcp`: `list_items`, `get_item`, `open_item`, `claim_item`, `submit_result`, `review_result`, and `cancel_item`. `deadline_minutes` is an integer from 5 to 1440 and defaults to 360. Item text grants no authority. A result stays `unverified` until the sender records a checked acceptance (`checked_by_requester`). Cancellation sends no remote signal.
- Grok bearer credentials and Dot OAuth grants (migration `0003_participant_credentials.sql`). `scripts/grok-credential.mjs` writes SQL to issue or revoke the Grok bearer and does not apply it. Dot uses `GET` and `POST /authorize`, `POST /token`, and the OAuth discovery documents. `scripts/connect-code.mjs` writes SQL to issue or expire a Dot connect code and does not apply it (migration `0004_connect_code.sql`). The only accepted OAuth client is ChatGPT's.
- `POST /mcp` authenticates the Grok bearer or the Dot access token before any item is read or changed. A Dot token is accepted only when its scope equals the scope stored for that grant.
- A nullable `item.delivered_at` column (migration `0005_item_receipt.sql`). A recipient's first read stamps it once. Item reads fail closed when the column is absent.
- A per-item authority envelope (migration `0006_authority_envelope.sql`). `item` gains nullable `envelope_json` and `envelope_sha256`. The stored JSON includes `scope.allowed_sources` and `scope.allowed_resources`. The `item_audit` triggers block updates and replacement of retained rows; retention may delete rows older than 90 days. `item_audit_head` tracks the latest `seq`. Credential revocation is separate: it updates `participant_credential.revoked_at` in place.
- Optional signed wake for `grok_bot` after a new open, submit, or review. The secret name is `WAKE_SECRET_GROK_BOT`. The body is `type`, `item_id`, and `occurred_at`. Polling is the source of truth. A missing wake logs `wake.not_configured`.
- Workers Rate Limiting bindings. Unauthenticated limit 60 and authenticated limit 120, each per 60 seconds. A missing or rejected binding returns 503 `rate_limit_unavailable`. `POST /owner/claim` spends its address bucket only after the site check and a well-formed `Bootstrap-Secret`.
- Daily retention at `0 0 * * *`. Open and claimed items past their deadline are stored as `expired`. A finished row is deleted 30 days after its last change.
- Operator runbook `docs/test-instance.md` for a separate test Worker. Nine safety invariants in `docs/INVARIANTS.md`, each with a test. Released migrations `0001`–`0006` are pinned by `scripts/migration-guard.mjs`. CI runs gitleaks, that guard, lint, test, and build. CI does not deploy.
- AGPL-3.0-only. Contributions use the Developer Certificate of Origin. A `Signed-off-by` line for the commit author may appear anywhere in the message.
- Basic scope is Grok Bot, Dot (ChatGPT), and Claude. The code on main implements all three; migration `0007_claude_basic_participant.sql` ships in the repo, and once a pinned tag exists the upgrade procedure applies it with `wrangler d1 migrations apply` when it is pending, before deploying the code that needs it.

#### Changed

- OAuth access-token and refresh lifetimes are pinned. Refresh keeps the scope stored for the grant. Token and MCP refusals are logged with a closed set of reasons.
- The secret scan walks the checked-out ref only.

#### Security

- The example Wrangler config sets `invocation_logs` to false, so headers such as `Bootstrap-Secret` are not stored in invocation logs.
- No signing key is in this repository. A release checkout is pinned by tag plus the full commit SHA. Signatures are not available.

#### Not in this candidate

These are absent on `main`. They are not deliverables of this candidate.

- A git tag or a GitHub release.
- An environment kill switch. Stopping a participant is `participant.enabled = 0`.
- Down migrations. `0005` leaves `delivered_at` in place when the Worker is rolled back. `0006` leaves `envelope_json`, `envelope_sha256`, `item_audit`, and `item_audit_head` in place.
