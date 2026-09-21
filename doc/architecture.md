# Architecture

## Overview

SCG is a Go CLI that prevents supply chain attacks by enforcing dependency integrity and secret least-privilege in CI/CD pipelines. The CLI queries the SCG Platform API for all data — no registry tokens, no local resolution, no configuration needed.

```
User Interface        scg init | check | scope | audit
                           |
Logic Layer           parser/ -> platform/client.go -> manifest/
                           |
SCG Platform          api.scg.data-insights.ai
                           |
Data Engine           TKG TieredStore (32,000+ tools, 30 profiles)
```

## Core Design Decisions

### 1. Platform-Only Resolution

The CLI never calls GitHub, Docker Hub, PyPI, or npm directly. All resolution goes through the SCG Platform, which continuously crawls and indexes CI/CD tools. This means:

- Zero configuration for users (no `GITHUB_TOKEN`, no registry accounts)
- Pre-computed results (sub-millisecond responses)
- Centralized drift detection across all users
- Rate tiers scale with subscription, not registry limits

### 2. Two Independent Defense Layers

```
Layer 1: Manifest Enforcement
  "Is this dependency the same binary we approved?"
  Detects: tag hijacking, typosquatting, dependency confusion

Layer 2: Secret Scoping
  "Does this tool need access to this secret?"
  Prevents: credential theft, lateral movement, privilege escalation
```

Either layer alone breaks a supply chain attack. Together, they make it structurally impossible.

### 3. Temporal Drift Detection

The platform stores resolution history using temporal edges in a knowledge graph. When `actions/checkout@v4` resolves to a different commit SHA than yesterday, that's drift — possibly a tag hijack.

The CLI doesn't run graph queries — it calls `GET /v1/resolve` and compares the result to what's locked in `scg.lock`.

### 4. Lockfile Is the Portable Artifact

Users interact with:
- `scg.lock` — a human-readable JSON lockfile (committed to git)
- CLI commands — `scg init`, `scg check`, `scg scope`
- Exit codes — 0 (clean), 1 (drift/violations), 2 (SCG could not complete; not a finding)

## Package Structure

```
cmd/scg/           CLI entry point — dispatches to subcommands
resolver/          Resolver interface and ecosystem types
parser/            Extract refs from CI/CD config files
  workflow.go      GitHub Actions YAML parser
manifest/          Lockfile lifecycle
  manifest.go      Data model: Lockfile, ToolEntry, Signature
  lock.go          Read/write scg.lock (JSON)
  sign.go          Ed25519 signing + platform signing
  drift.go         Compare locked vs. live digests
scoper/            Secret access policy engine
  env.go           Environment variable scanning and matching
platform/          SCG Platform API client
  client.go        HTTP client with caching (5 min TTL)
  resolver.go      PlatformResolver implements resolver.Resolver
  types.go         API request/response types
internal/config/   Configuration from environment
```

## Data Flow

### `scg init`

```
1. Discover workflow files (parser/)
2. Parse each file -> ToolRef[], SecretRef[], StepDef[]
3. For each ToolRef:
   a. Resolve reference -> digest via platform /v1/resolve
   b. Record in lockfile structure
4. Sign lockfile via platform /v1/sign (ed25519-platform)
   Falls back to local ephemeral ed25519 if platform unreachable
5. Write scg.lock
```

### `scg check`

```
1. Read scg.lock
2. Verify the platform signature against the key compiled into the CLI
3. For each ToolEntry in lockfile:
   a. Re-resolve reference via platform /v1/resolve
   b. Compare live digest vs. locked digest
   c. If different: CRITICAL drift (possible tag hijack)
4. A tool the platform cannot answer for, or whose digest is past its freshness budget, is reported unverified
5. Report results
6. Exit 0 (clean), 1 (drift) or 2 (nothing could be verified: an SCG failure, not a finding)
```

### `scg scope`

```
1. Parse workflows to find the named step and its tool
2. Fetch security profile from platform /v1/profile
3. Scan local environment for secret-like variables
4. Match secrets against profile's forbidden regex patterns
5. Report violations
6. Optionally: clear forbidden env vars inside the scg process (--sanitize;
   later commands are separate processes and are unaffected)
```

## Signing Model

### Platform Signing (default)

The platform signs lockfiles with a persistent ed25519 key. Verification via `GET /v1/pubkey`.

There is no local fallback: if the platform cannot sign, `scg init` fails. The
key inside the lockfile is informational; verification uses the platform key
compiled into the CLI (`manifest.PlatformPublicKey`), so a lockfile signed by
any other key is rejected.

## Supported Ecosystems

| Ecosystem | Config Files | Status |
|---|---|---|
| GitHub Actions | `.github/workflows/*.yml` | Implemented |
| Docker | `Dockerfile` | Implemented |
| PyPI | `requirements.txt`, `pyproject.toml` | Implemented |
| npm | `package.json`, `package-lock.json` | Implemented |
| Go | `go.mod`, `go.sum` | Planned |
| Helm | `Chart.yaml` | Planned |
