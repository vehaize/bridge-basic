# Security

ADMRN Bridge is pre-alpha. Report suspected vulnerabilities in private.

## Contact

Email hg@admrn.com.

## Response time

The goal is to acknowledge a report within 7 days. That is a goal, not a guarantee. Phase 0 has no on-call rotation.

## In scope

- The Worker, tests, CI, and docs in this repository.
- What `GET /health` returns.
- Secrets, account identifiers, or the owner email committed to this repository.

## Out of scope

- An operator's Cloudflare account, private `wrangler.jsonc`, domain, and billing.
- The product site at admrn.com. This repository does not host it.
- A finding that needs a credential this repository does not contain.
- Public GitHub issues for a suspected vulnerability.

## What to send

- What you found and the impact you expect.
- The commit or version you looked at.
- Enough detail for a maintainer to reproduce the issue on their own deployment.

Do not include live secrets, account identifiers, or a proof aimed at someone else's deployment.

## Please do not

- Open a public GitHub issue for a suspected vulnerability.
- Publish the details before maintainers have had a reasonable time to confirm and fix the issue.

Phase 0 has no bug-bounty program.

The owner-email lock is specified in the companion design document, `docs/design/owner-lock.md`.
