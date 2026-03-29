# Signing Model

## Current: Ephemeral Ed25519

SCG currently signs lockfiles with an ephemeral ed25519 keypair generated at `scg init` time. The private key exists only in memory and is discarded after signing. The public key is embedded in the lockfile.

### What this proves
- **Tamper detection**: If anyone modifies the lockfile after signing, the signature breaks.
- `scg check` verifies the signature is valid against the embedded public key.

### What this does NOT prove
- **Identity**: You cannot verify WHO signed the lockfile. Each `scg init` run generates a new keypair. An attacker could generate their own keypair, sign a malicious lockfile, and it would pass verification.
- **Chain of trust**: There's no connection between lockfile version N and version N+1. A completely different key signs each one.

### Why this is acceptable for now
The lockfile is committed to git. Git's own integrity (commit signing, branch protection) provides the identity layer. If you trust your git history, you trust the lockfile. The ed25519 signature prevents post-commit tampering (e.g., a compromised CI cache serving a modified lockfile).

## Planned: OIDC + JWKS (Platform Tier)

The SCG Platform will add identity-bound signing:

```
1. CI provides OIDC token (GitHub Actions, GitLab CI, etc.)
2. SCG Platform verifies the JWT signature via JWKS from the issuer
3. Platform validates claims: issuer, subject, expiration, not-before
4. Platform signs the lockfile with its own key (not ephemeral)
5. Lockfile contains: platform signature + verified OIDC identity
6. Verification checks: platform signature + OIDC identity matches policy
```

This proves both integrity AND identity. The platform's signing key is the trust anchor, not an ephemeral key.

### Why not do OIDC in the CLI?

We tried it. It was security theater. The CLI can extract OIDC claims from a JWT token, but without JWKS verification, it can't prove the token is genuine. An attacker could forge an OIDC token with arbitrary claims, and the CLI would accept it.

Real OIDC verification requires:
1. Fetching the JWKS keyset from the issuer's well-known endpoint
2. Cryptographically verifying the JWT signature against the keyset
3. Checking token expiration and audience

This is networking infrastructure (HTTP client, key caching, retry logic) that belongs in the platform, not a CLI tool that should work offline.

### VerifyOIDCClaims (available now)

The `manifest.VerifyOIDCClaims()` function validates the structural and temporal claims of an OIDC JWT:
- Checks issuer is present
- Checks expiration (`exp`) against current time
- Checks not-before (`nbf`) with 30-second skew tolerance

This is used by the platform tier for claim validation after JWKS signature verification.

## Signature Format

```json
{
  "signature": {
    "algorithm": "ed25519",
    "value": "base64-encoded-ed25519-signature",
    "public_key": "base64-encoded-ephemeral-public-key"
  }
}
```

The signature covers the entire lockfile content with the `signature` field set to null. Any modification to any field invalidates the signature.

## Verification

```bash
# Signatures are mandatory by default
scg check                    # fails if unsigned
scg check --no-verify        # skips verification (not recommended)
```
