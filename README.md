# Supply Chain Guardian (SCG)

**Know when the software you trust changes.**

SCG records the dependencies of a project as resolved fingerprints, signed by the platform, and reports when what the project uses stops matching that record. A single binary; it runs on your own machine as readily as in a pipeline.

- **A reviewed baseline** — `scg init` resolves every supported dependency to a content hash and records it in a signed `scg.lock`. What the baseline does not cover is printed, so an uncovered dependency does not read as a covered one.
- **Drift detection** — `scg check` re-resolves the recorded entries and reports a reference that now resolves to different content: a moved tag, a republished version.
- **Selection checking** — the same command compares what the project declares today with what the baseline recorded, so a dependency added after the review is a finding rather than something the drift pass never looks at.
- **Secret scoping** — each tool's profile names the credentials it needs and the ones it must not see. `scg audit` reports the ones a step can reach. It reports exposure; it does not isolate it.

What this is not: SCG does not intercept installs, inspect processes, or establish that a dependency is free of malicious code. A matching fingerprint says the artifact did not change, not that it is safe, and a first baseline records whatever was there when you ran it.

## Quick Start

### Install

```bash
# Binary (Linux/macOS)
curl -sSL https://scg.data-insights.ai/install.sh | sh

# From source
git clone https://github.com/data-insights-ai/rho-scg.git
cd rho-scg && make build
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
      - uses: data-insights-ai/rho-scg@v0.3.0
        with:
          mode: check

      # Scope secrets before each sensitive step
      - uses: data-insights-ai/rho-scg@v0.3.0
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

Published CI/CD supply chain attacks and the mechanism each one used, newest first.

These rows map a mechanism to the layer that addresses that mechanism. They are not
replays: no incident below was reproduced against a released SCG build, and the
column says which layer applies, not that the attack was tested and blocked.

| Attack | Date | What Happened | Impact | Layer that addresses the mechanism |
|---|---|---|---|---|
| **tj-actions/changed-files** | Mar 2025 | GitHub Action tags force-pushed to malicious commits; CI secrets stolen | 23,000+ repos, CISA KEV | A rewritten tag resolves to different content, so the recorded entry no longer matches; the secret audit reports the credential the step did not need |
| **reviewdog/action-setup** | Mar 2025 | Action tag hijacked, leaking PAT that cascaded to tj-actions | CISA KEV, multiple downstream actions | A rewritten tag no longer matches the recorded entry; the secret audit reports what the step could reach |
| **PyTorch torchtriton** | Dec 2022 | Dependency confusion: public PyPI package squatted internal name; exfiltrated SSH keys | 2,700+ downloads in 5 days | Manifest pins source registry + content digest; registry switch detected |
| **Codecov Bash Uploader** | Jan-Apr 2021 | CI script modified to exfiltrate all env vars via `$(env)` | 29,000+ customers, undetected 2 months | A modified script no longer matches the recorded entry; the secret audit reports the variables the step could read |
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

Which layer addresses which mechanism. "Applies" means the mechanism is the kind of
change that layer compares, not that the incident was replayed against a released build.

| Attack | Date | Recorded baseline | Secret scoping | Drift detection |
|---|---|:---:|:---:|:---:|
| tj-actions + reviewdog | Mar 2025 | Applies | Reports exposure | Applies |
| PyTorch confusion | Dec 2022 | Applies | Reports exposure | Applies |
| Codecov | Jan-Apr 2021 | Applies | Reports exposure | Applies |
| ua-parser-js | Oct 2021 | Applies | - | Applies |
| event-stream | Nov 2018 | Applies | - | Applies |
| PyPI typosquatting | 2022-2025 | Applies | - | Applies |

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

Each CI tool has a **security profile** defining what secrets it legitimately needs. `scg scope` reports which forbidden secrets the step can see. `--sanitize` clears those variables inside the `scg` process; the command that runs next is a separate process and still inherits them from the shell or the runner, so stop the job on the exit code rather than relying on removal. Restricting the credential in the step that runs the tool is what actually isolates it.

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
| `scg init` | Scan workflows, resolve all dependencies, write `scg.lock` | 0 = success, 2 = operational |
| `scg check` | Verify the baseline signature, compare the project's current dependencies with the baseline, and compare the recorded entries with live state | 0 = clean, 1 = drift or a dependency outside the baseline, 2 = operational |
| `scg update` | Re-resolve all dependencies, update `scg.lock` | 0 = success, 2 = operational |
| `scg scope --step NAME` | Report which forbidden secrets a step can see (`--sanitize` clears them inside scg only) | 0 = clean, 1 = violations, 2 = operational |
| `scg audit` | Full security report (drift + secret exposure) | 0 = clean, 1 = issues, 2 = operational |
| `scg watch [--repo NAME]` | Upload the signed `scg.lock` so the platform watches its tools for this repository (needs a key) | 0 = watching, 2 = operational |
| `scg unwatch [--repo NAME \| --all]` | Stop watching a repository, or every repository | 0 |
| `scg watches [--json]` | List watched repositories and tools | 0 |
| `scg intel [--watched\|--private] [--stix]` | Drift and burst events: the public feed, only your watched tools, or your organization's private feed | 0 |
| `scg login` / `scg logout` | Sign this machine in to your organization by browser, or with `--password --email ADDR` on a machine that has neither browser nor mail (stores a key, owner-only), or forget it | 0 |
| `scg version` | Print version | 0 |

`--json` on `init`, `check`, `scope`, `audit` and `watches` prints a structured
result with the same exit code the terminal run would have. `check` and
`audit` include the findings: `summary` (total, verified, drifted, unverified),
`drift[]` (ecosystem, reference, both hashes, severity, detail) and
`unverified[]`; `scope` includes `violations[]`, the tool and where its profile
came from (`seed` for a hand-written profile, `derived` for one read from the action's own manifest, plus `+override` when your organization's override applied).

`init --watch` and `update --watch` upload the lockfile right after writing it.
The repository name comes from `--repo`, `SCG_REPO`, `GITHUB_REPOSITORY`,
`CI_PROJECT_URL` or the git remote, in that order. Watching more repositories
than the plan allows, or reading the private feed on a plan without it, exits
2 with the plan that would allow it; that is never reported as a finding.

## Configuration

Zero-config by default. Optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `SCG_API_KEY` | (none) | API key of your organization; without it `scg login` credentials are used, else anonymous (25 dependency resolutions an hour per address) |
| `SCG_PASSWORD` | (none) | Password for `scg login --password`, so no secret reaches the shell history or a process listing |
| `SCG_REPO` | (detected) | Repository name for `watch`, e.g. `github.com/acme/app` |
| `SCG_PLATFORM_URL` | `https://api.scg.data-insights.ai` | Platform API endpoint |
| `SCG_LOCKFILE` | `scg.lock` | Lockfile path |
| `SCG_WORKFLOW_DIR` | `.github/workflows` | Workflow directory |
| `SCG_LOG_LEVEL` | `info` | debug, info, warn, error |

`GITHUB_TOKEN` is not read by the CLI. All resolution goes through the platform,
which holds the registry credentials server-side; you need no GitHub token,
Docker Hub account or registry credentials of any kind.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean — everything verified |
| 1 | Finding — drift detected, or a secret violation |
| 2 | Operational — SCG could not complete the check (platform unreachable, budget spent, or its data too old to trust) |

Fail your build on 1. Retry on 2: it says nothing about your dependencies, only
about SCG's availability.

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
scg check  # your organization's limit: 100/hr Free, 5,000/hr Pro, 50,000/hr Enterprise, shared by all its keys
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
