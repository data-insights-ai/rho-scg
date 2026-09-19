# Signing Model

## Platform signing with a pinned key

`scg init` and `scg update` send the canonical lockfile bytes to the platform
(`POST /v1/sign`); the platform signs them with its persistent ed25519 key and
returns algorithm `ed25519-platform`, the signature and its public key.
`scg check` verifies the signature against the platform public key compiled
into the CLI (`manifest.PlatformPublicKey`), never against the key inside the
file. A lockfile that is unsigned, signed with another algorithm, or signed by
any other key is rejected; there is no bypass flag and no local signing
fallback (if the platform cannot sign, `scg init` fails).

### What this proves
- **Tamper detection**: any change to the lockfile after signing breaks the
  signature.
- **Origin**: the signature could only have been produced by the SCG platform.
  An attacker cannot mint a passing lockfile with a key of their own.

### What this does not prove
- **Who asked for the signature**: the platform signs for any caller. The
  identity layer is git: commit signing and branch protection on the repository
  that holds `scg.lock`.

## Signature format

```json
{
  "signature": {
    "algorithm": "ed25519-platform",
    "value": "base64-encoded-ed25519-signature",
    "public_key": "base64-encoded-platform-public-key"
  }
}
```

The signature covers the entire lockfile content with the `signature` field set
to null.

## Verification

```bash
scg check          # fails on a missing, foreign or invalid signature
```

## Identity-bound signing

Binding a signature to a CI identity (OIDC token verified against the issuer's
JWKS, then signed by the platform) is a design note, not a shipped feature or a
plan tier. It belongs in the platform, which has the network access to verify
tokens; a CLI-only check of JWT claims proves nothing and was removed.
