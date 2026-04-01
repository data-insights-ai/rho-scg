# Supply Chain Guardian (SCG)

**Prevent supply chain attacks before they reach your pipeline.**

SCG enforces dependency integrity and secret least-privilege across CI/CD pipelines. Single binary. Zero config. Two independent defense layers that would have stopped every major CI/CD supply chain attack of the past seven years.

- **Digest pinning** — locks every dependency to an immutable content hash. Tag hijacking, dependency confusion, and typosquatting are structurally impossible.
- **Secret scoping** — enforces least-privilege per CI step. A scanner cannot read publish tokens. A linter cannot access cloud credentials.
- **Drift detection** — catches any change between what you approved and what runs. The SCG Platform tracks dependency state continuously across all supported ecosystems.

## Quick Start

### Install

```bash
# Binary (Linux/macOS)
curl -sSL https://scg.data-insights.ai/install.sh | sh

# From source
git clone https://github.com/data-insights-ai/rho-scg.git
cd supply-chain-guardian && make build
```

### Lock your dependencies

```bash
scg init                          # scan workflows, resolve, write scg.lock
git add scg.lock && git commit -m "Add supply chain lockfile"
```

### Verify in CI

```yaml
# .github/workflows/ci.yml
jobs:
  build:
    steps:
      - uses: actions/checkout@v4

      # Verify all dependencies before anything runs
      - uses: data-insights-ai/scg-action@v1
        with:
          mode: check

      # Scope secrets before each sensitive step
      - uses: data-insights-ai/scg-action@v1
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
    Status:  TAG HIJACK — same tag, different commit

  Build HALTED. Exit code: 1
```

---

## Why SCG?

Software supply chain attacks are not theoretical. They are happening now, at scale, hitting thousands of organizations. SCG exists because every major attack of the past seven years shares the same root causes — and the same fix.

### The Attack That Started It All

On March 14, 2025, the **TeamPCP** attack compromised `tj-actions/changed-files` by force-pushing malicious code to 350+ existing tags. The compromised action harvested CI secrets from **23,000+ repositories**. Stolen PyPI tokens were used to publish backdoored packages. CISA added it to the Known Exploited Vulnerabilities catalog.

The attack cascaded from an earlier compromise of `reviewdog/action-setup`, where a hijacked `@v1` tag leaked the PAT that unlocked the tj-actions attack. One mutable tag, two compromised organizations, 23,000 victims.

**Two failures enabled this:**
1. Tags are mutable. The same `@v1` pointed to different commits before and after the attack.
2. Every CI step had access to every secret. A scanner could read publish tokens.

| Attack Step | SCG Defense |
|---|---|
| Force-push tag to malicious commit | `scg check`: digest mismatch, build halted |
| Compromised action reads all secrets | `scg scope`: publish tokens stripped from scanner environment |
| Stolen token publishes backdoored package | Token was never exposed |

Either layer alone breaks the kill chain.

### Real-World Attacks SCG Stops

Every major CI/CD supply chain attack of the past seven years. Sorted newest-first.

| Attack | Date | What Happened | Impact | SCG Defense |
|---|---|---|---|---|
| **tj-actions/changed-files** | Mar 2025 | GitHub Action tags force-pushed to malicious commits; CI secrets stolen | 23,000+ repos, CISA KEV | Digest pinning rejects rewritten tag; secret scoping strips credentials |
| **reviewdog/action-setup** | Mar 2025 | Action tag hijacked, leaking PAT that cascaded to tj-actions | CISA KEV, multiple downstream actions | Digest pinning catches tag rewrite; secret scoping limits blast radius |
| **PyTorch torchtriton** | Dec 2022 | Dependency confusion: public PyPI package squatted internal name; exfiltrated SSH keys | 2,700+ downloads in 5 days | Manifest pins source registry + content digest; registry switch detected |
| **Codecov Bash Uploader** | Jan-Apr 2021 | CI script modified to exfiltrate all env vars via `$(env)` | 29,000+ customers, undetected 2 months | Digest catches script tampering; secret scoping blocks `$(env)` exfiltration |
| **ua-parser-js** (npm) | Oct 2021 | npm account hijacked; cryptominer + credential stealer published | 7M+ weekly downloads | Digest pinning rejects unexpected content hash |
| **event-stream** (npm) | Nov 2018 | Maintainer socially engineered; malicious transitive dependency added | 8M malicious installs over 2.5 months | Manifest locks full dependency tree; new transitive dep rejected |
| **PyPI typosquatting** | 2022-2025 | Sustained campaigns: 500+ fake packages in a single 2024 wave | 10,000+ malicious downloads per campaign | Manifest allowlist rejects unknown packages |

### The Pattern

Every attack above exploits the same structural weakness:

```
Mutable reference (tag, version, script URL)
     + Excessive privilege (secrets available to all steps)
     + No integrity verification (trust the registry)
     = Supply chain compromise
```

### Kill Chain Analysis

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
<summary><b>ua-parser-js npm Hijack (October 2021)</b></summary>

```
Attack Chain                          SCG Defense
──────────────────────────────────    ────────────────────────────────
1. Attacker hijacks npm account        (Account security — outside
   of ua-parser-js maintainer          SCG scope)

2. Malicious versions published        scg check: DRIFT DETECTED
   with cryptominer + password         → Content hash doesn't match
   stealer                              locked digest
                                      Attack stopped at step 2.

3. 7M+ weekly downloaders pull         SCG-locked projects reject the
   trojanized package                   package — wrong hash

4. Password-stealing trojan            Never installed
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
   private index — malicious           → Source registry changed
   package installed                   → Content hash mismatch
                                      Attack stopped at step 2.

3. Malware exfiltrates SSH keys,      scg scope: build tool profile
   .gitconfig, /etc/passwd via         forbids SSH_*, restricts env
   encrypted DNS queries               exposure

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

2. CI pipeline installs               scg check: BLOCKED
   typosquatted package                → Package not in manifest
                                      Attack stopped at step 2.

3. Malware deploys zgRAT, steals     Never installed — manifest
   crypto wallets and browser          rejects unknown packages
   credentials

4. 500+ fake packages in single       All rejected — none match
   2024 wave                           any locked digest
```
</details>

### Coverage Matrix

| Attack | Date | Digest Pinning | Secret Scoping | Drift Detection |
|---|---|:---:|:---:|:---:|
| tj-actions + reviewdog | Mar 2025 | Stops it | Limits blast radius | Stops it |
| PyTorch confusion | Dec 2022 | Stops it | Limits blast radius | Stops it |
| Codecov | Jan-Apr 2021 | Stops it | Limits blast radius | Stops it |
| ua-parser-js | Oct 2021 | Stops it | - | Stops it |
| event-stream | Nov 2018 | Stops it | - | Stops it |
| PyPI typosquatting | 2022-2025 | Stops it | - | Stops it |

**Digest pinning alone stops all 7 attacks. Secret scoping provides defense-in-depth for the 3 that specifically target CI secrets.**

---

## How It Works

### Layer 1: Manifest Enforcement

SCG resolves every mutable reference to an immutable content digest and records it in `scg.lock`. On every CI run, `scg check` re-resolves and compares. If any digest changed, the build halts.

```
actions/checkout@v4  -->  sha256:b4ffde65...  (immutable)
trivy-action@v1      -->  sha256:57a97c7e...  (immutable)
```

### Layer 2: Secret Scoping

Each CI tool has a **security profile** defining what secrets it legitimately needs. `scg scope` identifies forbidden secrets, and with `--sanitize` actually removes them from the environment before the next step runs.

```
trivy-action profile:
  Needs:    GITHUB_TOKEN (read:packages)
  Forbids:  PYPI_*, NPM_TOKEN, DOCKER_HUB_PASSWORD, AWS_SECRET_*
```

### SCG Platform

The SCG Platform at `api.scg.data-insights.ai` continuously crawls and pre-computes digests for all known CI/CD tools across all supported ecosystems. The CLI queries the platform for every resolution — no GitHub token, no Docker Hub account, no registry credentials needed. The platform also hosts curated security profiles for secret scoping.

---

## Commands

| Command | Purpose | Exit Code |
|---|---|---|
| `scg init` | Scan workflows, resolve all dependencies, write `scg.lock` | 0 = success |
| `scg check` | Validate `scg.lock` against live state | 0 = clean, 1 = drift |
| `scg update` | Re-resolve all dependencies, update `scg.lock` | 0 = success |
| `scg scope --step NAME` | Audit secrets for a step (add `--sanitize` to remove them) | 0 = clean, 1 = violations |
| `scg audit` | Full security report (drift + secret exposure) | 0 = clean, 1 = issues |
| `scg version` | Print version | 0 |

## Configuration

Zero-config by default. Optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `SCG_API_KEY` | (none) | SCG Platform subscription key (higher rate limits) |
| `SCG_PLATFORM_URL` | `https://api.scg.data-insights.ai` | Platform API endpoint |
| `SCG_LOCKFILE` | `scg.lock` | Lockfile path |
| `SCG_WORKFLOW_DIR` | `.github/workflows` | Workflow directory |
| `SCG_LOG_LEVEL` | `info` | debug, info, warn, error |

## Supported Ecosystems

| Ecosystem | Config Files | Status |
|---|---|---|
| GitHub Actions | `.github/workflows/*.yml` | Implemented |
| Docker | `Dockerfile`, `*.dockerfile` | Implemented |
| npm | `package-lock.json` | Implemented |
| PyPI | `requirements.txt`, `requirements-*.txt` | Implemented |
| Go | `go.mod`, `go.sum` | Planned |
| Helm | `Chart.yaml` | Planned |

## SCG Platform

The CLI queries the SCG Platform (`api.scg.data-insights.ai`) for all dependency resolution and security profile lookups. No local resolution, no registry credentials, no fallback. If the platform is unreachable, the check fails — this is by design.

```bash
# Works out of the box (20 req/hr anonymous)
scg check

# Higher rate limits with an API key
export SCG_API_KEY=scg_live_xxx
scg check  # 5,000 req/hr (Pro)
```

---

## Documentation

| Document | Contents |
|---|---|
| [Architecture](doc/architecture.md) | Platform-first design, data flow, package structure |
| [Security Model](doc/security-model.md) | Threat model, trust boundaries, input validation |
| [OIDC Signing](doc/oidc-signing.md) | Keyless signing with CI OIDC tokens |
| [Getting Started](doc/getting-started.md) | Installation, first run, CI integration |
| [Lockfile Spec](doc/lockfile-spec.md) | `scg.lock` format, fields, signing |
| [SKILL.md](SKILL.md) | Agent/tool integration interface |

## Development

```bash
make build    # compile binary
make test     # unit tests
make ci       # full: fmt + vet + build + race tests
make cover    # coverage report
```

Requirements: Go 1.26+

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Priority areas: ecosystem parsers, CI platform integrations.

## Security

- **Vulnerabilities:** security@data-insights.ai
- **Signing:** ed25519 + OIDC keyless (planned)
- **Dependencies:** minimal tree, audited with `govulncheck`

See [doc/security-model.md](doc/security-model.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
