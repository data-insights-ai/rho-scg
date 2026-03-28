# Lockfile Specification (`scg.lock`)

## Overview

The `scg.lock` file records the immutable content digests of all CI/CD dependencies. It is:
- **JSON** — human-readable, git-diffable
- **Signed** — tamper-evident via ed25519 or OIDC keyless signatures
- **Committed** — checked into version control as the source of truth

## Format

```json
{
  "version": 1,
  "generated_at": "2026-03-28T10:00:00Z",
  "pipelines": [
    {
      "path": ".github/workflows/ci.yml",
      "type": "github_actions",
      "steps": [
        {
          "name": "checkout",
          "job": "build",
          "order": 0,
          "tools": [
            {
              "ecosystem": "github_action",
              "reference": "actions/checkout@v4",
              "hash": "b4ffde65f46336ab88eb53be808477a3936bae11",
              "algorithm": "sha256",
              "source": "api.github.com"
            }
          ],
          "secrets": []
        },
        {
          "name": "trivy-scan",
          "job": "build",
          "order": 1,
          "tools": [
            {
              "ecosystem": "github_action",
              "reference": "aquasecurity/trivy-action@v1",
              "hash": "57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
              "algorithm": "sha256",
              "source": "api.github.com"
            }
          ],
          "secrets": [
            {
              "name": "GITHUB_TOKEN",
              "source": "secrets"
            }
          ]
        }
      ]
    }
  ],
  "signature": {
    "algorithm": "ed25519",
    "value": "base64-encoded-signature",
    "public_key": "base64-encoded-public-key"
  }
}
```

## Fields

### Top Level

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | integer | Yes | Lockfile format version (currently `1`) |
| `generated_at` | string (RFC 3339) | Yes | When this lockfile was created/updated |
| `pipelines` | array | Yes | All scanned CI/CD pipelines |
| `signature` | object | No | Cryptographic signature |

### Pipeline Entry

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | Yes | File path relative to repo root |
| `type` | string | Yes | CI system: `github_actions`, `gitlab_ci`, etc. |
| `repo` | string | No | Repository identifier |
| `steps` | array | Yes | Steps with resolved dependencies |

### Step Entry

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Step name (from workflow or auto-generated) |
| `job` | string | Yes | Job containing this step |
| `order` | integer | Yes | Position within the job |
| `tools` | array | Yes | Resolved tool references |
| `secrets` | array | No | Secret references found in this step |

### Tool Entry

| Field | Type | Required | Description |
|---|---|---|---|
| `ecosystem` | string | Yes | `github_action`, `docker`, `pypi`, `npm`, `go`, `helm` |
| `reference` | string | Yes | Original mutable reference (e.g., `actions/checkout@v4`) |
| `hash` | string | Yes | Immutable content digest |
| `algorithm` | string | Yes | Hash algorithm (e.g., `sha256`) |
| `source` | string | No | Where the resolution was performed |

### Secret Entry

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Secret name (e.g., `GITHUB_TOKEN`) |
| `source` | string | Yes | Where it comes from: `secrets`, `env`, `vars` |

### Signature

| Field | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | Yes | `ed25519` or `oidc+ed25519` |
| `value` | string | Yes | Base64-encoded signature |
| `public_key` | string | For ed25519 | Base64-encoded public key |
| `issuer` | string | For OIDC | OIDC issuer URL |
| `subject` | string | For OIDC | OIDC subject claim |

## Signing

The signature covers the entire lockfile content with the `signature` field set to `null`. This ensures any modification to any field invalidates the signature.

### Verification Steps

1. Parse the lockfile
2. Remove the `signature` field
3. Marshal the remaining content to JSON (canonical form)
4. Verify the signature against the embedded public key (ed25519) or OIDC JWKS (keyless)

## Version History

| Version | Changes |
|---|---|
| 1 | Initial format |
