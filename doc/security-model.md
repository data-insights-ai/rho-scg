# Security Model

## Threat Model

SCG defends against supply chain attacks targeting CI/CD pipelines. The primary threats are:

### T1: Tag Hijacking
**Attack:** Attacker gains write access to a dependency repository and force-pushes malicious code to existing tags.
**Example:** TeamPCP (March 2025) — compromised `tj-actions/changed-files` by rewriting tags.
**Defense:** `scg check` detects when a mutable reference resolves to a different digest than when it was locked.

### T2: Secret Exfiltration via Compromised Dependencies
**Attack:** A compromised CI tool reads environment secrets it doesn't need (e.g., a scanner reading publish tokens).
**Defense:** `scg scope` enforces least-privilege by stripping secrets the tool's profile marks as forbidden.

### T3: Dependency Confusion / Typosquatting
**Attack:** Attacker publishes a package with a name similar to a legitimate internal dependency.
**Defense:** `scg check` validates the exact digest of every dependency. A different package = different digest = drift detected.

### T4: Compromised Registry
**Attack:** A package registry is compromised and serves altered binaries for existing versions.
**Defense:** `scg check` compares content digests, not version numbers. Altered binaries have different hashes.

## Trust Boundaries

```
Untrusted                          Trusted
────────────────────────────────── ────────────────────
Package registries (npm, PyPI)     scg.lock (signed, committed)
GitHub Actions marketplace         SCG Platform (pre-verified data)
Docker Hub                         SCG binary
CI environment variables           Platform signature (pinned key)
```

### What SCG Trusts
- The `scg.lock` file (after signature verification)
- The SCG Platform API
- The initial resolution performed during `scg init` (human-reviewed before commit)

### What SCG Does NOT Trust
- Mutable references (tags, branches, version strings)
- Package registry responses (verified against locked digests)
- CI environment variables (scanned and filtered)
- Unknown tools (warned, not automatically blocked)

## Signing Security

### Platform signature
- The platform signs every lockfile with its persistent ed25519 key (`POST /v1/sign`); the CLI holds no signing key
- The CLI verifies against the platform public key compiled into the binary, in constant time; the key inside the lockfile is informational
- The signature covers the entire lockfile content (excluding the signature field itself)
- An unsigned lockfile, or one signed by any other key, is an error; there is no bypass flag

## Input Validation

- YAML parsing uses `gopkg.in/yaml.v3` with no custom unsafe options
- HTTP responses from registries are decoded with bounded readers
- Regex patterns in DSM profiles are compiled and validated before use
- File paths are validated to prevent directory traversal

## Fail-Open vs. Fail-Closed

**Default: Fail-open for adoption, fail-closed for security.**

- Unknown tools (no DSM profile): **warn** but allow (fail-open)
- Unsigned lockfile: **error** on `scg check` (fail-closed)
- Digest mismatch: **halt** the build (fail-closed)
- GitHub API failure: **error** with clear message (fail-closed)
- `--strict` flag: treats all warnings as errors (full fail-closed)

## Vulnerability Reporting

Report security vulnerabilities to: **security@data-insights.ai**

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.
