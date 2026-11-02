# Release signing

No release signing key exists. This repository does not contain a private key, a public key, or a key fingerprint. Do not generate one while installing, and do not commit one.

## What an installer can check now

1. Use a git tag and the full 40-character commit SHA published with that release. Do not install from `main` or from a tag you have not checked.
2. Check out that SHA. `git rev-parse HEAD` must print the same SHA. That SHA is the checksum of the commit you are about to use.
3. Run `npm ci`. It installs the lockfile and checks each dependency's integrity hash.

There is no detached signature to verify. A missing signature is not a successful check, and it is not a reason to skip the SHA check.

## Plan

When the owner chooses to sign releases:

1. The owner creates the signing key outside this repository. The private key stays off this repository, off CI, and out of chat.
2. Publish the public-key fingerprint in this document. Until that fingerprint is written here, signature verification is not possible.
3. Each release publishes a `SHA256SUMS` file for the tagged commit and a detached signature over that file.
4. Installers check the signature against the published fingerprint, then check the checksum, then confirm the commit SHA.

TODO: public key fingerprint. No key has been created. Do not invent a fingerprint.

CI does not sign releases and does not hold a signing key.
