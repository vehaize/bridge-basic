# Contributing

Contributions come in by pull request. Open the request against `main` from a feature branch.

## Developer Certificate of Origin

Every commit needs a `Signed-off-by: Name <email>` line for that commit's author. `git commit -s` adds the line for the configured name and email. The sign-off certifies the [Developer Certificate of Origin](https://developercertificate.org/) version 1.1:

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

The line must match the commit author's name and email exactly. The check accepts that line anywhere in the message. A sign-off from someone else, or a longer line that only contains the sign-off, does not count. Pull request checks compare `base..head` and fail when a commit in that range lacks a valid sign-off. A merge commit is different: the check still reads only its last trailer block and accepts any well-formed `Signed-off-by` line there. Maintainers should not merge a pull request that fails the check.

Commits made before the DCO switch were made by the project owner and his own agents.

Please also follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Checks

Use Node.js `^22.13.0 || >=24`. CI installs `>=22.13.0 <23`. `npm test` uses `--experimental-strip-types`, which Node.js added in 22.6.0.

```sh
npm ci
npm run lint
npm test
npm run build
```

GitHub Actions runs those three scripts. It does not deploy. Before install, it also runs `node scripts/lockfile-funding.mjs --check`.

`postinstall` runs `node scripts/lockfile-funding.mjs`. That removes `funding` from `package-lock.json` after `npm ci` and after `npm install` with no package arguments. npm writes those fields back on the next install. `fund=false` does not stop that. The check fails when a tracked file contains a funding URL. `npm install <package>` does not run root lifecycle scripts. Run `node scripts/lockfile-funding.mjs` after that command.

## Configuration hygiene

Keep real Wrangler configuration, `.dev.vars`, receipts, and logs out of git. `.gitignore` already excludes them. The tracked Wrangler file is [`wrangler.example.jsonc`](wrangler.example.jsonc), and its account, D1, KV, domain, and owner-email values stay placeholders.

If you change bindings in that template, run `npm run lint` so Wrangler regenerates `worker-configuration.d.ts` before the type check. That file is gitignored. Do not hand-write an `Env` interface and do not commit the generated file.

## Security reports

Use the private path in [SECURITY.md](SECURITY.md). Do not file a public issue for a vulnerability.
