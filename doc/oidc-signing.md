# OIDC Keyless Signing

## Overview

SCG supports keyless lockfile signing using OIDC tokens from CI environments. No long-lived private keys to manage, rotate, or protect. The CI provider's identity proves who signed the lockfile.

## How It Works

```
CI Environment                          SCG
──────────────────                      ─────────────
1. CI provides OIDC token
   (JWT with issuer + subject claims)
                                        2. Detect OIDC token from env
                                        3. Extract issuer + subject claims
                                        4. Generate ephemeral ed25519 keypair
                                        5. Sign lockfile with ephemeral private key
                                        6. Embed in lockfile:
                                           - ed25519 signature
                                           - ephemeral public key
                                           - OIDC issuer URL
                                           - OIDC subject claim
                                        7. Throw away ephemeral private key
```

The ephemeral private key exists only in memory for the duration of the signing operation. It is never written to disk, never stored, never reused.

## Verification

To verify an OIDC-signed lockfile:

1. Check `signature.algorithm == "oidc+ed25519"`
2. Verify the ed25519 signature against the embedded ephemeral public key
3. Check that the OIDC issuer matches your expected CI provider
4. Check that the OIDC subject matches your expected repository/workflow

Step 2 proves the lockfile wasn't tampered with. Steps 3-4 prove who signed it.

## Supported CI Providers

| CI Provider | Environment Variable | Issuer |
|---|---|---|
| GitHub Actions | `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | `https://token.actions.githubusercontent.com` |
| GitLab CI | `CI_JOB_JWT_V2` | GitLab instance URL |
| Generic | `OIDC_TOKEN` | Depends on provider |

SCG auto-detects the OIDC token by checking these environment variables in order. If none is found, it falls back to ephemeral ed25519 signing (no identity binding).

## GitHub Actions Setup

To use OIDC signing in GitHub Actions, your workflow needs the `id-token: write` permission:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write    # Required for OIDC signing
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: scg init    # Automatically uses OIDC signing
```

The OIDC token contains claims like:
```json
{
  "iss": "https://token.actions.githubusercontent.com",
  "sub": "repo:owner/repo:ref:refs/heads/main",
  "aud": "https://github.com/owner/repo",
  "repository": "owner/repo",
  "workflow": "CI"
}
```

SCG embeds `iss` and `sub` in the lockfile signature, allowing verification that the lockfile was signed during a specific workflow run in a specific repository.

## Lockfile Signature Format

### OIDC-signed lockfile

```json
{
  "signature": {
    "algorithm": "oidc+ed25519",
    "value": "base64-encoded-ed25519-signature",
    "public_key": "base64-encoded-ephemeral-public-key",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:owner/repo:ref:refs/heads/main"
  }
}
```

### Ed25519-signed lockfile (fallback)

```json
{
  "signature": {
    "algorithm": "ed25519",
    "value": "base64-encoded-ed25519-signature",
    "public_key": "base64-encoded-public-key"
  }
}
```

## Security Properties

| Property | OIDC Keyless | Ed25519 Keypair |
|---|---|---|
| Key management | None — ephemeral keys | Must protect private key |
| Identity binding | CI identity proven via OIDC claims | No identity — anyone with the key |
| Tamper evidence | Ed25519 signature | Ed25519 signature |
| Works offline | No — needs CI OIDC provider | Yes |
| Works locally | No — no OIDC token available | Yes |

## Fallback Behavior

SCG automatically selects the signing method:

1. If `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `CI_JOB_JWT_V2`, or `OIDC_TOKEN` is set → OIDC keyless
2. Otherwise → ephemeral ed25519 (no identity binding)

This means `scg init` on a developer machine uses ed25519, and the same command in CI uses OIDC. No configuration needed.

## Limitations

- **No transparency log.** SCG does not currently record signing events in a Rekor-like transparency log. The OIDC claims are embedded in the lockfile but not publicly auditable. Transparency log support is planned for the platform tier.
- **No JWKS verification at sign time.** SCG extracts OIDC claims without verifying the JWT signature during signing. Full JWKS-based verification is performed at check time (when the lockfile is validated). This is intentional — the CI environment is trusted at sign time.
- **Token expiry.** OIDC tokens have short lifetimes (typically 5-15 minutes). The token must be valid when `scg init` runs. SCG does not refresh tokens.
