# Supply Chain Guardian (SCG)

**Prevent supply chain attacks before they reach your pipeline.**

SCG is a single-binary CLI that enforces dependency integrity and secret least-privilege across CI/CD pipelines. It detects tag hijacking, blocks unauthorized secret exposure, and ships as a GitHub Action, GitLab CI step, or standalone tool.

```bash
$ scg init

  Scanning .github/workflows/ci.yml ...
  Found 6 dependencies across 4 ecosystems

  Resolving digests:
    actions/checkout@v4             sha256:b4ffde65
    aquasecurity/trivy-action@v1    sha256:57a97c7e
    docker/build-push-action@v5     sha256:2cdde995
    pypa/gh-action-pypi-publish@v1  sha256:81e9d935

  Secret exposure analysis:
    Step "trivy-scan" has access to PYPI_API_TOKEN
      Trivy does not publish to PyPI (blocked by profile)
    Step "publish" correctly scoped to PYPI_API_TOKEN only

  Written: scg.lock (4 entries, signed)
```

---

## Why SCG?

On March 14, 2025, the **TeamPCP** attack compromised the popular `tj-actions/changed-files` GitHub Action by force-pushing malicious code to existing tags. The compromised action harvested CI secrets from **23,000+ repositories** and used stolen PyPI tokens to publish backdoored packages.

**Two independent failures enabled this:**
1. Tags are mutable. The same `@v1` tag pointed to different commits before and after the attack.
2. Every CI step had access to every secret. Trivy (a scanner) could read PyPI publish tokens.

SCG prevents both:

| Attack Step | SCG Defense |
|---|---|
| Force-push tag to malicious commit | `scg check`: digest mismatch detected, build halted |
| Compromised action reads all secrets | `scg scope`: PYPI_API_TOKEN stripped from scanner environment |
| Stolen token publishes backdoored package | Token was never exposed to the scanner |

Either layer alone breaks the kill chain. Together, they make this class of attack structurally impossible.

---

## Quick Start

### Install

```bash
# Binary (Linux/macOS)
curl -sSL https://scg.dev/install.sh | sh

# Go
go install gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/cmd/scg@latest

# From source
git clone https://github.com/bds421/supply-chain-guardian.git
cd supply-chain-guardian && make build
```

### Lock your dependencies

```bash
# Scan workflows and create scg.lock
scg init

# Commit the lockfile
git add scg.lock && git commit -m "Add supply chain lockfile"
```

### Verify in CI

```yaml
# .github/workflows/ci.yml
jobs:
  build:
    steps:
      # Verify all dependencies before anything runs
      - uses: bds421/scg-action@v1
        with:
          mode: check

      # Scope secrets before each sensitive step
      - uses: bds421/scg-action@v1
        with:
          mode: scope
          step-name: trivy-scan

      - uses: aquasecurity/trivy-action@sha256:57a97c7e...
```

### Catch a tag hijack

```bash
$ scg check

  CRITICAL DRIFT DETECTED

  aquasecurity/trivy-action@v1
    Locked:  sha256:57a97c7e7821a5776cebc9bb87c984fa
    Live:    sha256:ff00bad1337cafe0000000000000000000
    Status:  TAG HIJACK - same tag, different commit

  Build HALTED. Exit code: 1
```

---

## How It Works

### Layer 1: Manifest Enforcement

SCG resolves every mutable reference (tags, branches, version strings) to an immutable content digest and records it in `scg.lock`. On every CI run, `scg check` re-resolves and compares. If any digest changed without a version bump, the build halts.

```
actions/checkout@v4  -->  sha256:b4ffde65...  (immutable)
trivy-action@v1      -->  sha256:57a97c7e...  (immutable)
```

### Layer 2: Secret Scoping

Each CI tool has a **security profile** defining what secrets it legitimately needs. Before a step runs, `scg scope` strips any secrets the tool shouldn't see.

```
trivy-action profile:
  Needs:    GITHUB_TOKEN (read:packages)
  Forbids:  PYPI_*, NPM_TOKEN, DOCKER_HUB_PASSWORD, AWS_SECRET_*
```

Even if Trivy is compromised, the PyPI token was never in its environment.

### Powered by a Temporal Knowledge Graph

Under the hood, SCG models your dependency graph using a [temporal knowledge graph](doc/architecture.md). Dependencies, digests, secrets, and their relationships are tracked over time. Drift detection is a temporal query, not a string comparison.

This means SCG can answer questions like:
- "When did this tag last change?" (temporal history)
- "What's the blast radius if this action is compromised?" (graph traversal)
- "Has this tool been stable for 30 days?" (temporal reasoning)

---

## Commands

| Command | Purpose | Exit Code |
|---|---|---|
| `scg init` | Scan workflows, resolve all dependencies, write `scg.lock` | 0 = success |
| `scg check` | Validate `scg.lock` against live state | 0 = clean, 1 = drift |
| `scg update` | Re-resolve all dependencies, update `scg.lock` | 0 = success |
| `scg scope --step NAME` | Audit and sanitize secrets for a step | 0 = clean, 1 = violations |
| `scg audit` | Full security report (drift + secret exposure) | 0 = clean, 1 = issues |
| `scg version` | Print version | 0 |

---

## Configuration

SCG is zero-config by default. Optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | (none) | GitHub API authentication (avoids rate limits) |
| `SCG_API_KEY` | (none) | SCG Platform subscription key |
| `SCG_LOCKFILE` | `scg.lock` | Lockfile path |
| `SCG_WORKFLOW_DIR` | `.github/workflows` | Workflow directory |
| `SCG_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |

---

## SCG Platform

The open-source CLI resolves dependencies locally. The **SCG Platform** (optional subscription) adds:

| Feature | Free (CLI) | Pro (Platform) |
|---|---|---|
| Local dependency scanning | Unlimited | Unlimited |
| Pre-computed hashes (no API rate limits) | - | Instant |
| Curated security profiles | Top 50 embedded | Thousands |
| Continuous drift monitoring | At CI time only | Real-time alerts |
| Resolution history | - | 90-day temporal history |
| Dashboard | - | Web UI across all repos |

```bash
# Enable platform (one env var)
export SCG_API_KEY=scg_live_xxx
scg check  # now uses pre-computed hashes + full profile library
```

---

## Supported Ecosystems

| Ecosystem | Parser | Resolver | Status |
|---|---|---|---|
| GitHub Actions | `.github/workflows/*.yml` | GitHub API (tag -> SHA) | Phase 1 |
| Docker | `Dockerfile` | Docker Registry API | Phase 2 |
| PyPI | `requirements.txt`, `pyproject.toml` | PyPI API | Phase 2 |
| npm | `package.json`, `package-lock.json` | npm Registry | Phase 2 |
| Go | `go.mod`, `go.sum` | go.sum delegation | Phase 2 |
| Helm | `Chart.yaml` | Helm Chart Registry | Phase 3 |

---

## Architecture

SCG is built on a temporal knowledge graph ([TKG](https://gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3)) with a [Cypher query engine](https://gitlab2024.bds421-cloud.com/bds421/sigma/tkgd). The graph is invisible to users but enables powerful security analysis.

See [doc/architecture.md](doc/architecture.md) for the full technical design.

---

## Development

```bash
# Build
make build

# Test
make test

# Full CI check
make ci

# Coverage report
make cover
```

Requirements: Go 1.26+

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

**Priority areas:**
- New ecosystem parsers and resolvers
- Security profile contributions (DSM profiles)
- CI/CD platform integrations
- Documentation improvements

---

## Security

SCG is a security tool. We take its own security seriously.

- **Reporting vulnerabilities:** Email security@bds421.dev with details
- **Signing:** All releases are signed. Lockfiles support ed25519 and OIDC keyless signatures
- **Dependencies:** Minimal dependency tree. All deps audited with `govulncheck`

See [doc/security-model.md](doc/security-model.md) for the full threat model.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).
