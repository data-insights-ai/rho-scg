# Security

SCG exists to catch supply-chain attacks, so a weakness in it matters
more than in most tools. Please report one privately.

- **Contact:** security@data-insights.ai
- **What to include:** the version (`scg version`), the command, what you
  expected and what happened. A proof of concept helps; a working exploit
  against the public platform is not needed and please do not run one.
- **Response:** we acknowledge within two working days and keep you
  informed until the fix ships. Fixes go out as a release with a
  changelog entry crediting the reporter unless you prefer otherwise.

## What is in scope

- The CLI (`scg`): lockfile parsing, signature verification, the secret
  scoping that removes forbidden secrets from a step's environment.
- The GitHub Action (`action.yml`): install and checksum verification.
- The public platform at `api.scg.data-insights.ai` as this CLI uses it.

## What the CLI trusts

The CLI verifies lockfile signatures against an ed25519 platform key
compiled into the binary, and compares pinned hashes with what the
platform resolves. It holds no registry credentials. A finding that lets
a lockfile verify without the platform's signature, or a stale platform
answer pass as verified, is the kind of report we most want.
