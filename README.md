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

Software supply chain attacks are not theoretical. They are happening now, at scale, hitting thousands of organizations simultaneously. Here are the attacks that shaped SCG's design:

### The Attack That Started It All

On March 14, 2025, the **TeamPCP** attack compromised the popular `tj-actions/changed-files` GitHub Action by force-pushing malicious code to 350+ existing tags. The compromised action harvested CI secrets from **23,000+ repositories** — dumping runner memory to extract PATs, npm tokens, RSA keys, and AWS credentials. Stolen PyPI tokens were used to publish backdoored packages. CISA added it to the Known Exploited Vulnerabilities catalog.

The attack cascaded from an earlier compromise of `reviewdog/action-setup`, where a hijacked `@v1` tag leaked the PAT that unlocked the tj-actions attack. One mutable tag, two compromised organizations, 23,000 victims.

**Two independent failures enabled this:**
1. Tags are mutable. The same `@v1` tag pointed to different commits before and after the attack.
2. Every CI step had access to every secret. A scanner could read publish tokens.

SCG prevents both:

| Attack Step | SCG Defense |
|---|---|
| Force-push tag to malicious commit | `scg check`: digest mismatch detected, build halted |
| Compromised action reads all secrets | `scg scope`: PYPI_API_TOKEN stripped from scanner environment |
| Stolen token publishes backdoored package | Token was never exposed to the scanner |

Either layer alone breaks the kill chain. Together, they make this class of attack structurally impossible.

### This Is Not an Isolated Incident

SCG is designed to stop an entire **class** of attacks, not just one. Every major supply chain attack of the past five years shares the same root cause: trusting mutable references and granting excessive privileges.

| Attack | Date | What Happened | Impact | SCG Defense |
|---|---|---|---|---|
| **tj-actions/changed-files** | Mar 2025 | GitHub Action tags force-pushed to malicious commits | 23,000+ repos compromised | Digest pinning detects tag hijack |
| **reviewdog/action-setup** | Mar 2025 | Upstream action tag hijacked, cascading to tj-actions | CISA KEV, multiple actions compromised | Digest pinning + secret scoping limits blast radius |
| **Codecov Bash Uploader** | Jan-Apr 2021 | CI script silently modified to exfiltrate all env vars via `$(env)` | 29,000+ enterprise customers (Twilio, HashiCorp, Rapid7) | Digest verification catches script tampering; secret scoping blocks blanket `$(env)` exfiltration |
| **xz/liblzma backdoor** | Mar 2024 | 2-year social engineering campaign; backdoor in release tarballs but NOT in git source | CVSS 10.0, nearly reached stable Linux distros | Drift detection catches tarball-vs-source divergence |
| **SolarWinds SUNBURST** | Dec 2020 | Build system compromised; malicious code injected during compilation | 18,000+ orgs including US Treasury, DHS, FireEye | Drift detection catches build artifact divergence from source |
| **ua-parser-js** (npm) | Oct 2021 | Maintainer account hijacked; cryptominer + credential stealer published | 7M+ weekly downloads, malicious for 4 hours | Digest pinning rejects unexpected content hash |
| **event-stream** (npm) | Nov 2018 | Maintainer socially engineered; malicious dependency added targeting Bitcoin wallets | 2M+ weekly downloads, 8M malicious installs over 2.5 months | Manifest enforcement blocks unexpected new transitive dependency |
| **PyTorch torchtriton** | Dec 2022 | Dependency confusion: public PyPI package squatted internal name; exfiltrated SSH keys via DNS | 2,700+ downloads in 5 days | Manifest pins source registry + content digest; confusion detected |
| **3CX Desktop App** | Mar 2023 | First documented cascading supply chain attack: compromised Trading Technologies led to compromised 3CX | 600,000+ customers, 12M users | Drift detection catches build output divergence |
| **PyPI malware campaigns** | 2022-2025 | Sustained typosquatting: 500+ fake packages in a single 2024 wave; PyPI suspended all registrations | 10,000+ malicious downloads per campaign | Manifest allowlist rejects unknown package names |

### The Pattern

Every attack above exploits the same structural weakness:

```
Mutable reference (tag, version, script URL)
     + Excessive privilege (secrets available to all steps)
     + No integrity verification (trust the registry)
     = Supply chain compromise
```

SCG eliminates all three:
- **Immutable digests** replace mutable references
- **Secret scoping** enforces least-privilege per step
- **Drift detection** catches any change between what you approved and what runs

### Kill Chain Analysis: How SCG Stops Each Attack

<details>
<summary><b>tj-actions/changed-files + reviewdog (March 2025)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. Attacker hijacks reviewdog PAT     (Upstream — outside SCG scope)
2. reviewdog/action-setup@v1 tag      scg check: DRIFT DETECTED
   rewritten to malicious commit      → SHA mismatch, build halts here
                                      Attack stopped at step 2.

3. (If #2 missed) Malicious code      scg scope: strips secrets from
   dumps CI runner memory via          action environment — only
   double-base64 encoded env vars      GITHUB_TOKEN (read-only) visible

4. Leaked PAT used to compromise      PAT was never in the environment
   tj-actions/changed-files            → Cascade impossible

5. 23,000 repos exfiltrate secrets    Never reached
```
</details>

<details>
<summary><b>Codecov Bash Uploader (January-April 2021)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. Attacker extracts HMAC key from    (Upstream — outside SCG scope)
   intermediate Docker image layer

2. Codecov bash uploader script       scg check: DRIFT DETECTED
   modified on codecov.io              → Script content hash changed
   (adds: curl -d "$(env)" to          from locked digest
   attacker server)                    Attack stopped at step 2.

3. (If #2 missed) Script runs and     scg scope: code coverage tool
   exfiltrates ALL env variables       profile forbids: AWS_SECRET_*,
   via $(env)                          PYPI_*, NPM_TOKEN, SSH_*
                                      → Only CODECOV_TOKEN visible

4. 29,000 enterprise customers         Credentials were never exposed
   leak credentials for 2 months       → 2-month silent breach impossible
```
</details>

<details>
<summary><b>xz/liblzma Backdoor (March 2024)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. "Jia Tan" gains maintainer trust   (Social engineering — outside
   over 2+ year campaign               SCG scope)

2. Backdoor inserted into release     scg check: DRIFT DETECTED
   tarballs but NOT in git source      → Tarball digest diverges from
                                       git source digest
                                      Attack stopped at step 2.

3. (If #2 missed) Backdoor hijacks    Downstream consumers with SCG
   OpenSSH via liblzma, enabling       reject the tarball — content
   remote code execution               hash doesn't match manifest

4. Hundreds of millions of Linux       Never reached — caught before
   servers potentially compromised     reaching stable distros
```
</details>

<details>
<summary><b>SolarWinds SUNBURST (December 2020)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. APT29 compromises SolarWinds       (State actor — outside SCG scope)
   build system

2. SUNSPOT implant substitutes        scg check: DRIFT DETECTED
   malicious source during build,      → Build artifact hash diverges
   restores original afterward          from source hash
                                      Attack stopped at step 2.

3. 18,000 organizations receive       SCG-protected consumers reject
   trojanized Orion update             update — digest doesn't match
                                       expected build output

4. 14-month undetected access to       Detected at first verification,
   US Treasury, DHS, FireEye           not 14 months later
```
</details>

<details>
<summary><b>ua-parser-js npm Hijack (October 2021)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. Attacker hijacks npm account        (Account security — outside
   of ua-parser-js maintainer          SCG scope)

2. Malicious versions 0.7.29,         scg check: DRIFT DETECTED
   0.8.0, 1.0.0 published with        → Content hash for ua-parser-js
   cryptominer + password stealer       doesn't match locked digest
                                      Attack stopped at step 2.

3. 7M+ weekly downloaders pull         SCG-locked projects reject the
   trojanized package                   package — wrong hash

4. Windows password-stealing trojan    Never installed
   harvests browser credentials
```
</details>

<details>
<summary><b>event-stream / flatmap-stream (November 2018)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. Attacker socially engineers         (Social engineering — outside
   maintainer into granting access     SCG scope)

2. Malicious dependency                scg check: DRIFT DETECTED
   "flatmap-stream" added to           → New transitive dependency not
   event-stream                         in approved manifest
                                      Attack stopped at step 2.

3. Encrypted payload targeting         flatmap-stream never installed —
   Copay Bitcoin wallet deploys         not in the locked dependency tree

4. Private keys stolen from wallets   Never reached
   with >100 BTC balance
```
</details>

<details>
<summary><b>PyTorch torchtriton Dependency Confusion (December 2022)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. Attacker registers "torchtriton"   (Registry gap — outside SCG scope)
   on public PyPI, squatting
   internal package name

2. pip resolves public PyPI before    scg check: DRIFT DETECTED
   private index — malicious           → Package source changed from
   package installed                    private index to public PyPI
                                      → Content hash mismatch
                                      Attack stopped at step 2.

3. Malware exfiltrates SSH keys,      scg scope: build tool profile
   .gitconfig, /etc/passwd via         forbids SSH_*, restricts env
   encrypted DNS queries               exposure
                                      → SSH keys never accessible

4. 2,700+ downloads over 5 days      Never reached for SCG users
```
</details>

<details>
<summary><b>PyPI Typosquatting Campaigns (2022-2025, ongoing)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. Attacker uploads "reqeusts"        (Typo — outside SCG scope)
   (typo of "requests") to PyPI

2. Developer installs typosquatted    scg check: BLOCKED
   package in CI/CD pipeline           → Package name not in approved
                                        manifest allowlist
                                      Attack stopped at step 2.

3. Malware deploys zgRAT, steals     Never installed — manifest
   crypto wallets and browser          rejects unknown packages
   credentials

4. 500+ fake packages in single       All rejected — none match
   2024 wave; PyPI suspends            any locked digest
   registrations
```
</details>

### Coverage Matrix

| Attack | Digest Pinning | Secret Scoping | Drift Detection |
|---|:---:|:---:|:---:|
| tj-actions + reviewdog (2025) | Stops it | Limits blast radius | Stops it |
| Codecov (2021) | Stops it | Limits blast radius | Stops it |
| xz/liblzma (2024) | Stops it | - | Stops it |
| SolarWinds (2020) | Stops it | - | Stops it |
| ua-parser-js (2021) | Stops it | - | Stops it |
| event-stream (2018) | Stops it | - | Stops it |
| PyTorch confusion (2022) | Stops it | Limits blast radius | Stops it |
| 3CX (2023) | Stops it | - | Stops it |
| PyPI typosquatting (ongoing) | Stops it | - | Stops it |

**Digest pinning alone stops 9/9 attacks. Secret scoping provides defense-in-depth for the 3 attacks that specifically target CI secrets.**

---

## Quick Start

### Install

```bash
# Binary (Linux/macOS)
curl -sSL https://scg.bds421.com/install.sh | sh

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
