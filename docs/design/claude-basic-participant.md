# Claude as a Basic participant

Design written before implementation, 2026-10-27. This supersedes the older
Phase 0 exclusion of Claude. Basic includes Grok Bot, Dot (ChatGPT), and Claude
on claude.ai. Claude receives the same item lifecycle as Dot. Engineering
execution, repository access, deployment, and an Advanced lane are outside this
change. The license remains AGPL-3.0-only.

## Item routing and authority

The authenticated participant is one of `grok_bot`, `dot`, or `claude`.
`open_item` accepts a `recipient` from that fixed set and rejects self-routing.
An omitted recipient keeps the existing Dot-to-Grok and Grok-to-Dot defaults;
Claude must name its recipient. All new templates name recipients explicitly.
The sender still comes only from a verified credential, never item arguments.

Every directed pair uses the same seven tools: list, get, open, claim, submit,
review, and cancel. An uninvolved third participant cannot read the item, stamp
delivery, claim, submit, review, or cancel it. Only the recipient may claim and
submit, and only the sender may review or cancel. An accepted claim replay has
`execute: false`. Results remain unverified until the sender records a checked
acceptance. Deadlines, caps, cancellation, audit, retention, and all-false Basic
authority flags retain their existing meaning.

The request digest binds the effective recipient for new routes. Existing
Dot/Grok requests retain their digest format and replay behavior; replay also
checks the stored recipient. Changing the recipient under the same sender and
idempotency key is a conflict. Inbox and sent filtering stay participant-bound.
There is no broadcast and no automatic delegation. Only Grok Bot has a wake;
Dot and Claude poll, and no new external notification destination is introduced.

## OAuth client and connection isolation

Keep the existing pinned `@cloudflare/workers-oauth-provider` 1.2.3. Add a fixed
client policy for Claude alongside the fixed ChatGPT policy:

| Participant | Client ID | Exact redirect URI |
| --- | --- | --- |
| `dot` | `https://chatgpt.com/oauth/client.json` | `https://chatgpt.com/connector_platform_oauth_redirect` |
| `claude` | `https://claude.ai/oauth/mcp-oauth-client-metadata` | `https://claude.ai/api/mcp/auth_callback` |

Claude's public metadata was read on 2026-10-27 and returned that client ID,
redirect, and `token_endpoint_auth_method: none`. Its [authentication
documentation](https://claude.com/docs/connectors/building/authentication)
requires advertised CIMD support and public-client `none` authentication to
select CIMD. The existing provider supplies these metadata fields, PKCE S256,
code exchange, audience verification, and rotating refresh tokens. Verify those
behaviors with synthetic metadata and the real pinned provider in tests.

The policy maps an exact client ID to a participant before consent. Unknown
clients and crossed client/redirect pairs fail before any metadata fetch or
credential write. No DCR endpoint, wildcard redirect, Claude Code loopback,
client secret, Anthropic API key, or account setup is introduced. Consent names
the participant and trusted client hostname; its CSP allows only the two fixed
hosted callback origins in addition to the bridge itself.

Generalize the existing connect-code implementation. The operator command gains
`--participant dot|claude`, defaulting to Dot for compatibility. Codes remain
single-use and owner-lock-bound. Every eligibility, claim, replay, spend, and
revocation query is participant-bound. Reconnecting Claude revokes only Claude's
previous credential, leaving Dot intact. The provider user ID, credential row,
token client ID, parsed token namespace, and stored grant must all agree. Every
MCP call and refresh issuance read D1 revocation, enablement, and current owner
binding. Refresh derives the participant from the provider-validated client and
user identity, then binds that participant to the credential row. A revoked,
disabled, missing, or stale-owner credential denies issuance without rotating or
revoking the stored KV grant. A D1 lookup failure also denies issuance and leaves
the grant available for retry after recovery.
Refresh preserves the exact stored ordered scope; a different scope fails
before token rotation. Existing lifetimes and consent idempotency stay intact.

## One forward schema change

Add only `migrations/0007_claude_basic_participant.sql`. Existing migrations are
immutable. The new file rebuilds the constrained participant, credential,
connect-code, item, and audit tables as needed to admit Claude. Preserve every
existing row and field, including envelope bytes/digests, delivered timestamps,
credentials, code spend markers, audit sequence numbers, and the audit head.
Preserve indexes, WITHOUT ROWID, unique active credentials, immutable envelopes,
anti-REPLACE guards, single delivery/expiry, and the `item_audit` protections
against updates and replacement of retained rows. Credential revocation remains
an in-place update of `participant_credential.revoked_at`.
Preserve the audit AUTOINCREMENT high-water mark even after retention removed
rows. Keep foreign-key enforcement valid through the rebuild. A repeated apply
must fail before changing data. No new credential or connect code is seeded.

The structural migration is one request, uses the existing migration guard
marker, and has no down file. It is authored and exercised only in disposable
in-memory test databases. No migration is applied to an operator database in
this task. Future installation requires a separately authorized operator rollout
with writes quiesced, backup/recovery evidence, and the matching Worker version.

## Verification

Synthetic tests cover all directed routes, third-party isolation, idempotency,
expiry, authority flags, OAuth cross-client rejection, connect-code isolation
and replay, revocation, refresh, and preservation of schema protections.
The SQL in the migration is exercised in disposable in-memory databases.
