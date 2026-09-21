# Changelog

All notable changes to Supply Chain Guardian are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scg login --password --email you@company.com` signs a machine in with
  an address and a password instead of the browser. The device flow needs
  somebody to approve a code in a browser, which suits a laptop and suits
  nothing else: an agent setting a project up, a CI image being built or
  a container with no browser and no mailbox could not sign in at all,
  and a person had to fetch a key and hand it over. The command signs in,
  mints one API key with the session it gets back, and stores that key
  where the device flow stores its own. The password comes from
  `SCG_PASSWORD` or from a prompt that does not echo, never from a flag,
  so no secret reaches the shell history or a process listing; it is not
  stored anywhere afterwards. Set the password once under Password in the
  account page.
- `poetry.lock`, `uv.lock` and `Pipfile.lock` are read, so a Python project
  is checked the way a Node one already was. `requirements.txt` is not a
  lock file: it names what somebody asked for, not what pip installed.
  One pinned line becomes a dozen packages in the environment, and every
  one of those is a package somebody can compromise, so checking only the
  pinned lines was checking the wrong thing. Measured with uv: FastAPI,
  SQLAlchemy, Pydantic, httpx and uvicorn are five requirements and
  nineteen packages; a Django, Celery, pandas, boto3, scikit-learn and
  JupyterLab stack is ten requirements and a hundred and thirty-three
  packages. Names are compared per PEP 503, so `Jinja2` and `jinja2`, and
  `zope.interface` and `zope-interface`, are one dependency. Development
  groups are included, because a compromised test dependency runs in the
  build like any other. A project with only a `requirements.txt` is now
  told plainly that its installed packages are not covered, and which
  command produces a lock file.

## [0.4.0] - 2026-09-21

### Added

- `scg init` asks the platform for the whole dependency set in one request
  per ecosystem instead of one request per dependency. Measured against a
  counting stub: a 40-dependency project cost 41 requests and now costs
  two, one batch and one signature. The plans sell API requests, so the
  cost of a command is measured in a test rather than estimated:
  `TestRequestCost_InitAndCheck` and `TestRequestCost_SignsOnce`.
- `scg check` compares what the project declares now with what the
  baseline recorded, and reports a dependency the baseline never reviewed
  or one it recorded that the project has dropped. Drift iterates the
  recorded entries, so a dependency added after the baseline was written
  never reached it: every entry could verify while the build pulled
  something nobody reviewed. Identity is the ecosystem and the reference
  together, never the hash alone. `-root` and `-workflows` say where the
  project is; when no project files are readable from there the
  comparison is reported as not performed rather than as removals.

### Changed

- The README no longer says the two layers "would have stopped every
  major CI/CD supply chain attack of the past seven years", that tag
  hijacking and typosquatting are "structurally impossible", or that
  secret scoping "strips credentials". None of that is established: the
  incident tables map a mechanism to the layer that compares that kind of
  change, and say so. The header states what the tool does and what it
  does not do.
- `scg init` no longer requires CI configuration. A missing or empty
  `.github/workflows` is "no workflows", not an error, and the supported
  project files (`package-lock.json`, `pnpm-lock.yaml`,
  `requirements*.txt`, `Dockerfile`) are read from the project root. The
  new `-root` flag names that root; without it, the conventional
  `.github/workflows` layout still names its own repository root and
  everything else uses the working directory. A project with no supported
  dependency is told so and gets no lockfile: an empty baseline passes
  every later check while covering nothing.
- `scg audit` verifies the baseline signature against the pinned platform
  key, exactly as `scg check` does, and reports completeness apart from
  findings. An audit with no baseline, with references it could not
  resolve, or with tools that have no profile now ends in `INCOMPLETE`
  and exit code 2 instead of `PASS`. The report names each item it could
  not check, and a clean result says how many baseline entries were
  compared.
- `scg scope --sanitize` says what it does. It clears the variables inside
  the `scg` process; the next command is a separate process that still
  inherits them, so the output no longer reports them as "REMOVED" and
  points at the exit code as the thing that gates the step. The action
  input, README, skill and architecture notes say the same.

### Fixed

- A Python requirement with a version range (`>=`, `~=`, `>`, a
  wildcard) was recorded as if it were pinned to the bound written in the
  file, so the baseline held a version the installer may never select and
  drift was compared against it. Only `==` and `===` produce a baseline
  entry now. Ranges, bare names and pnpm entries without a registry
  artifact are reported as not recorded, with the reason, and `scg init`
  prints them under "Not recorded" so uncovered dependencies do not read
  as covered ones.

## [0.3.1] - 2026-09-20

### Added

- Release binaries carry SLSA build provenance (`gh attestation verify
  scg-linux-amd64 --owner data-insights-ai`), beside the cosign-signed
  checksums.
- `--json` output carries `schema_version` (1). Additions keep the number;
  a rename or removal bumps it.
- `SECURITY.md`.

### Fixed

- In `--json` mode the human-readable report (the "Signature verified"
  line, the drift table) went to stdout with the JSON document, which made
  the output unparseable. It goes to stderr now; stdout is the document.
- Commands no longer call `os.Exit` from inside `--json` handling; they
  return the exit code to `main`, so those paths are tested.

### Removed

- `examples/demo` (the tag-hijack demonstration repositories).

### Changed

- A check, audit or init costs one platform request per ecosystem, not
  one per tool: the references are sent to `POST /v1/resolve/batch` first
  and the per-tool lookups come from the cache. Against an older platform
  without the endpoint the CLI asks one by one as before. Anonymous use
  (20 requests an hour per IP) now covers twenty runs, not two.
- Parser fixtures list current, advisory-free packages; the Dependabot
  exceptions for them are gone.

## [0.3.0] - 2026-09-19

The tags v0.2.0 and v0.2.1 were cut in March before 0.1.30 to 0.1.32; this
release continues from the highest tag.

### Added

- `scg watch`, `scg unwatch`, `scg watches`: register the signed lockfile with
  the platform per repository so its tools are watched (drift webhooks and the
  private feed are built on this). `init --watch` / `update --watch` do it in
  one step; the repository comes from `--repo`, `SCG_REPO`,
  `GITHUB_REPOSITORY`, `CI_PROJECT_URL` or the git remote. `init` records the
  repository in the lockfile's pipeline entry.
- `scg intel --watched`, `--private` and `--stix`: the feed narrowed to your
  watched tools, your organization's private feed, or STIX 2.1 output.
- `--json` now carries the findings: `summary`, `drift[]` and `unverified[]`
  for `check` and `audit`, `violations[]` plus the profile source for `scope`.
  Before, JSON mode only had the error string.
- A plan refusal from the platform (HTTP 402) exits 2 and names the plan that
  allows the feature; it is never reported as a finding.
- GitHub Action: inputs `watch` (upload after `init`) and `repo`.

- `dogfood` workflow: a scheduled canary that verifies our lockfile against the
  live platform every six hours and fails on any non-zero exit. CI on pushes
  now treats exit 2 as a warning, so platform state cannot block CLI merges.

### Changed

- `--json` reports the same exit code as the terminal run: an operational
  failure exits 2 with status `error`, a finding exits 1.
- The platform client sends the build version in its User-Agent (it said
  `scg/dev` in every release).
- Docs: command table lists `intel`, `login`, `logout`; exit code 2 documented
  everywhere; the signing model describes the pinned platform key (the CLI
  never verifies against the key inside the file); the "platform tier" that no
  plan defines is gone.

### Removed

- `platform.Client.Check` and the `CheckResponse`/`DriftEntry`/`HistoryEntry`
  types: the CLI verifies locally against `/v1/resolve` by design and nothing
  called them.
- `manifest.VerifyOIDCClaims`: JWT claim parsing without signature
  verification proves nothing and was wired to nothing.
- `.goreleaser.yml`: releases are built by `release.yml`; the file was never
  used.

### BREAKING

- **Lockfiles signed before this release no longer verify.** `scg check` now
  verifies against a platform public key compiled into the binary, and accepts
  only the `ed25519-platform` algorithm. Every existing lockfile was signed
  locally with an ephemeral key that was discarded immediately after signing,
  so nothing can attest to it.

  **Migration:** run `scg init` once, commit the regenerated `scg.lock`. The
  failure message names the cause:

  ```
  signature verification failed: lockfile signature algorithm is "ed25519",
  but only "ed25519-platform" is accepted — re-run 'scg init' against the
  platform to obtain a signed lockfile
  ```

  `scg init` now fails if the platform cannot sign, rather than falling back to
  a local key. A signature nobody can attest to is worse than no signature: it
  claims a property it does not have, and `check` reported it as verified.

- **`no-verify` input removed from the GitHub Action.** It appended a flag
  `scg check` never defined, so setting it aborted the run with
  `flag provided but not defined`. Signature verification has no bypass.

- **Exit code 2 introduced.** `check`, `init`, `update`, `audit` and `scope`
  now exit `2` for an operational failure — the platform was unreachable, the
  request budget was spent, or its data was too old to trust. Previously these
  exited `1`, indistinguishable from a real finding. **Pipelines that treat any
  non-zero exit as a detection will now report SCG outages as attacks;** fail
  the build on `1`, retry on `2`.

### Added

- **Pinned trust anchor** (`manifest.PlatformVerifier`). Verification uses a key
  compiled into the binary, overridable at build time via
  `-ldflags -X …manifest.PlatformPublicKey=…` for self-hosted deployments.
  Deliberately not overridable by environment variable: the threat model
  includes an attacker who can edit the workflow that would set it.
  `scg check` prints the key fingerprint, derived identically to the platform's
  own `key_id` so the two can be compared directly.
- **Staleness handling.** A digest matching a lockfile built from the same
  unrefreshed platform record proves nothing. `check` now reports stale answers
  as unverified rather than counting them clean.
- **`--sarif PATH`** on `check`, and a `sarif` input on the Action: findings
  reach GitHub code scanning instead of only a job log. Drift is an `error`,
  an unverifiable entry a `warning`.
- **`--timeout DURATION`** (default `5m`, `0` disables) on the network-bound
  commands. Without a ceiling a hung platform stalls for the product of the
  request timeout, the retry count and the reference count.
- **Release signing.** Release artifacts are signed with cosign keyless
  signing; `checksums.txt.sig` and `checksums.txt.pem` accompany each release.

### Changed

- **`check` resolves each distinct reference once**, with bounded concurrency.
  One action used across four steps previously cost four of the twenty requests
  an anonymous caller gets per hour.
- **Platform client**: retry with exponential backoff, `Retry-After` handling,
  sentinel errors (`ErrRateLimited`, `ErrUnauthorized`, `ErrNotFound`,
  `ErrUnavailable`) callers can branch on, a versioned `User-Agent`, a
  type-safe cache, and a refusal to send the API key over plaintext HTTP.
- **Lockfile I/O**: writes are atomic (temp file, fsync, rename); reads are
  size-capped at 8 MB, schema-validated, and reject unknown fields — content
  outside the schema was previously invisible to signature verification.
- **Scanned input files** are read through a bounded reader that refuses
  anything which is not a regular file. A named pipe called `ci.yml` in
  `.github/workflows` previously hung `scg init` until the CI job timed out.
- **Secret matching** compiles patterns once and treats an uncompilable pattern
  as a hard error. Skipping it silently permitted the secret the rule existed
  to block.
- **`LooksLikeSecret` matches whole words.** `MONKEY`, `AUTHOR`, `AWS_REGION`
  and `DOCKER_HOST` no longer register as secrets.
- **GitHub Action inputs pass through `env:`** and arguments are built as an
  array. They were interpolated into `run:` bodies, so a value derived from an
  issue title or a matrix entry became a command on the runner.
- **Both installers verify checksums or refuse to install.** `install.sh`
  previously warned and installed anyway when the checksum file could not be
  fetched or no sha256 tool was present.
- **Registry resolvers moved to the platform.** `rho-scg/resolver` now holds
  only the shared contract; the code that calls GitHub, Docker Hub, npm and
  PyPI lives where the credentials do, and no longer ships in a customer's
  binary. GitHub commit SHAs are now correctly labelled `sha1`, not `sha256`.

### Fixed

- `signViaPlat` built its own copy of the signing canonicalisation instead of
  calling `manifest.CanonicalJSON`. The two agreed by coincidence; the first
  added or reordered field would have invalidated every platform-signed
  lockfile in the field.
- All six `fs.Parse` error returns are checked.

### Internal

- `golangci-lint` (errcheck, staticcheck, errorlint, bodyclose, noctx) and
  `govulncheck` run in CI at 0 issues. `make cover-gate` enforces a 75% floor;
  coverage rose from 63% to 78%.
- CI dogfoods the tool against this repository's own lockfile.


## [0.1.32] - 2026-06-03

### Added
- **`scg intel` command**: shows recent threat-intel events (drift, bursts) from the platform's public `/v1/intel/recent` feed. `--limit N` (default 20) and `--json` for machine-readable output. No API key required (public feed). New `platform.Client.RecentIntel` + `platform.IntelEvent`.

## [0.1.31] - 2026-06-03

### Added
- **pnpm parser** (`parser/pnpm.go`): parses `pnpm-lock.yaml` (v6 with leading-slash keys like `/lodash@4.17.21`, v9 with bare `name@version` keys). Strips peer-dependency suffixes (`pkg@1.0.0(peer@2.0.0)` → `pkg@1.0.0`), handles scoped packages (`@scope/pkg`), and skips non-registry deps (directory/link/git) that carry no integrity. References are emitted without hashes — the resolver fills those in, matching the npm/PyPI parsers. 4 tests.
- **pnpm in multi-ecosystem init**: `scg init` now auto-discovers `pnpm-lock.yaml` in the repo root alongside `package-lock.json`, `requirements.txt`, and `Dockerfile`.

## [0.1.30] - 2026-04-01

### Added
- **npm parser** (`parser/npm.go`): parses `package-lock.json` (v1 with recursive dependencies, v2/v3 with flat packages map). Handles scoped packages (`@scope/pkg`). 8 tests + fuzz target.
- **PyPI parser** (`parser/pypi.go`): parses `requirements.txt` and `requirements-*.txt`. Supports `==`, `>=`, `~=` version operators. Strips extras, inline comments, environment markers, pip options. 10 tests + fuzz target.
- **Multi-ecosystem init**: `scg init` auto-discovers `package-lock.json`, `requirements.txt`, and `Dockerfile` in the repo root alongside workflow files. All ecosystems resolved through the platform in a single lockfile.
- **Multi-ecosystem test fixtures**: `internal/testutil/testdata_multi/` with workflows + npm + pypi for integration testing.

### Changed
- **Multi-resolver architecture**: `doInit`, `doAudit`, `resolveTools` accept `map[resolver.Ecosystem]resolver.Resolver` instead of a single resolver. Per-tool ecosystem routing via `buildResolvers()` (same pattern as `check.go`).
- **Removed `platformResolver()` function** from `main.go` — replaced by `buildResolvers()` which covers all 4 ecosystems (github_action, docker, npm, pypi).
- Test count: 119 -> 130 tests, 4 -> 6 fuzz targets. All race clean.

## [0.1.28] - 2026-03-30

### Added
- **Release pipeline**: GitHub Actions workflow builds, checksums, and publishes binaries on tag push. Server pulls from GitHub Releases via cron (no SSH keys needed).
- **Landing page**: click-to-copy install command, checksums section, Data Insights AI branding

### Changed
- **Defense layers section**: concise two-card layout matching the two-layer architecture

## [0.1.27] - 2026-03-30

### Changed
- **Removed graph dependencies**: eliminated `tkg/v3` and `tkgd` from CLI — dead code after platform-only pivot. Zero private dependencies. Builds anywhere.
- **Module path**: migrated to `github.com/data-insights-ai/rho-scg`
- **Domain migration**: all URLs from `scg.bds421.com` to `scg.data-insights.ai`
- **Binary size**: 18MB → 6.4MB (removed BadgerDB, protobuf, OpenTelemetry transitive deps)
- **Documentation rewrite**: all `.md` files updated for platform-only architecture
- **Sensitive data removed**: no server IPs or internal paths in open-source docs

### Removed
- `graph/` package (schema, store, queries)
- `dsm/` package (embedded profiles, client stub)
- `scoper/scoper.go` (Cypher-based Scope function, replaced by platform API)
- `vendor/` directory (all deps now public)

## [0.1.26] - 2026-03-30

### Security fixes
- **Partial verification fails (exit 1)**: if ANY tool cannot be verified (rate limit, platform down, not found), `scg check` now exits 1. Verification is all-or-nothing. Previously partial verification (95 of 100 tools) exited 0 — a security gap.

### Architecture cleanup
- **Removed local graph from init**: `scg init` no longer creates a TKG graph, bootstraps DSM, or populates nodes. Parse → resolve via platform → lockfile → sign → write. 508 → 240 lines.
- **Removed local graph from audit**: `scg audit` now uses platform `/v1/profile` for scoping (same as `scg scope`). No local graph, no DSM bootstrap, no Cypher queries. Consistent with the platform-only architecture.
- **All commands use platform only**: init, check, update, scope, audit — none create local graphs or call registries directly.

## [0.1.24] - 2026-03-30

### Changed
- **Both layers through the platform**: `scg check` (hashes) AND `scg scope` (profiles) now query the platform exclusively. No local graph, no DSM bootstrap, no Cypher queries in the CLI.
- **scg scope rewritten**: single platform API call to `/v1/profile` + local env scan + regex match. Removed 150+ lines of graph setup code.
- **No local resolvers anywhere**: removed all `NewGitHubResolver`, `NewDockerResolver`, `NewPyPIResolver`, `NewNPMResolver` from CLI. Removed `GITHUB_TOKEN` from config.
- **No fallback**: deleted `resolver/fallback.go`. Platform is the only resolver.
- **Errors always shown**: fixed silent error swallowing in main.go.
- **ProfileResponse type fixed**: matches actual platform API response (strings not objects, `forbidden_patterns` not `forbidden_secrets`).

## [0.1.23] - 2026-03-29

### Changed
- Quiet by default, `--verbose` for detailed logs
- Proper `--verbose` flag registered in every subcommand
- Clean warning messages (root cause only)
- Honest verification (fails when all tools skipped)
- Platform-first resolver (CLI queries api.scg.data-insights.ai by default)
- No GITHUB_TOKEN needed

## [0.1.17] - 2026-03-29

### Added
- **Platform integration**: `SCG_API_KEY=xxx scg check` routes all resolution through the SCG Platform API at `api.scg.data-insights.ai`. Pre-computed hashes, no registry rate limits.
- **Platform resolver** (`platform/resolver.go`): implements `resolver.Resolver` interface backed by platform API GET `/v1/resolve`.
- **Platform client** (`platform/client.go`): full implementation with GET, POST, auth headers, 10MB response limits, error handling for 401/403/404/429.
- **Response caching**: 5-minute TTL in-memory cache for platform API responses. Avoids redundant calls for the same tool within a check run.
- **Graceful fallback**: when `SCG_API_KEY` is set but platform is unavailable, `scg check` continues with warnings (partial failure). When not set, uses local resolvers as before.
- **`platform/types.go`**: `CheckResponse`, `DriftEntry` types for batch check API.

### Changed
- `buildResolvers()` in `check.go` auto-selects platform resolvers when `SCG_API_KEY` is set, local resolvers otherwise.
- Deploy docs updated for separate subdomains: `scg.data-insights.ai` (CLI), `api.scg.data-insights.ai` (platform).

## [0.1.14] - 2026-03-29

### Added
- `install.sh` — cross-platform install script (detects OS/arch, downloads binary, verifies checksum)
- `action.yml` — GitHub Action wrapper (check, scope, init, audit modes with all flags)
- `.goreleaser.yml` — cross-compile config for linux/darwin amd64/arm64 with checksums
- `tasks/todo.cli` — distribution task list (action, releases, install script, homebrew)

## [0.1.13] - 2026-03-29

### Fixed
- **Scope actually sanitizes**: `scg scope --sanitize` calls `os.Unsetenv()` for blocked secrets. Without flag, audit-only. README updated to match.
- **Graph sanity check**: `verifyGraphState()` runs after `populateGraph()` — checks pipeline and tool node counts match expectations. Fails with clear error if graph is incomplete.
- **Lockfile duplicate entries**: Steps with same name across different jobs (e.g., `test:checkout` and `security:checkout`) no longer produce duplicate tool entries. Fixed by keying on `job:step` instead of `step` alone. Found by dogfooding.
- **Profile coverage warning**: `scg scope` warns when a tool has no DSM profile loaded, with profile count for debugging.

### Added
- `.github/workflows/ci.yml` — SCG's own CI workflow for dogfooding
- `--sanitize` flag on `scg scope` (default: audit-only)
- Dogfooded `scg init` + `scg check` + `scg audit` on SCG's own repo — all pass

## [0.1.12] - 2026-03-29

### Fixed
- **No silently swallowed errors**: DSM `Bootstrap()` now validates all profile regex patterns at startup and returns profile count for sanity checking. Audit scope failures are now hard errors, not warnings. Lockfile read/drift errors in audit are hard errors.
- **DSM profile validation**: `ValidateProfiles()` checks for empty references, empty ecosystems, and invalid regex at bootstrap time — catches configuration bugs before graph population.
- **Documented CLI-to-platform limitations**: Added explicit section in `tasks/todo.platform` listing what the CLI can't do and how the platform solves each gap.

## [0.1.11] - 2026-03-29

### Fixed (second security review)
- **Canonical JSON signing**: Sign and verify now use shared `canonicalJSON()` — eliminates risk of serialization divergence between signing and verification paths
- **HTTP response body size limits**: All resolver HTTP clients capped at 10MB via `io.LimitReader` — prevents OOM from malicious registries
- **URL path encoding**: All resolver URLs use `url.PathEscape()` for package names, versions, owners — prevents path traversal injection
- **Audit uses all resolvers**: `scg audit` now checks Docker, PyPI, npm drift (was only GitHub)
- **Lockfile path validation**: `WriteLockfile` rejects paths containing `..` — prevents directory traversal via `--lockfile` flag
- **Honest scoper documentation**: `ScanEnv()` docstring clarifies it only identifies secrets, does not sanitize (caller's responsibility)
- **Docker ref parsing coupling documented**: Workflow parser's docker:// handling notes it must stay consistent with `resolver.parseDockerRef()`

## [0.1.10] - 2026-03-29

### Fixed (security review findings)
- **Signatures now mandatory by default.** Unsigned lockfiles fail `scg check`. Use `--no-verify` to skip (not recommended). Previously signatures were optional (default fail-open).
- **All 4 ecosystem resolvers registered in `scg check`.** Docker, PyPI, npm drift is now detected. Previously only GitHub Actions was checked — other ecosystems were silently skipped.
- **`docker://` images in workflows now parsed.** `uses: docker://alpine:3.19` is extracted as a Docker ecosystem dependency. Previously explicitly skipped with a TODO comment.
- **Partial failure in drift detection.** If one tool can't be resolved (API down, rate limited), other tools are still checked. Warnings report which tools were skipped. Previously one failure killed the entire check.
- **Removed OIDC signing theater.** `oidc+ed25519` signature algorithm removed — it embedded unverified OIDC claims, providing false sense of identity binding. CLI now uses honest ephemeral ed25519. Identity-bound signing (OIDC + JWKS verification) will be a platform-tier feature with real cryptographic verification.
- **`scg check` no longer bootstraps graph.** It reads the lockfile and re-resolves directly — no wasted DSM profile loading.

### Changed
- `--strict` flag renamed to `--no-verify` (inverted default: signatures now required)
- `VerifyOIDCClaims()` retained for platform-tier use (validates exp, nbf, issuer)
- `OIDCSigner` type removed (was security theater without JWKS verification)
- `Ed25519Verifier` only accepts `"ed25519"` algorithm (removed `"oidc+ed25519"`)

## [0.1.9] - 2026-03-28

### Added
- **Concurrent resolver tests**: 20 goroutines resolving different tools, 10 resolving same tool, parse function thread safety (200 concurrent calls), all race-clean
- **OIDC JWT verification**: `VerifyOIDCClaims()` validates expiration, not-before (with 30s skew tolerance), issuer presence. 6 new tests (valid, expired, not-yet-valid, missing issuer, no expiration, skew tolerance)
- **Real registry integration tests** (build tag `integration`): Docker Hub alpine+nginx, PyPI requests, npm express — all verified against live registries
- **Filesystem edge cases**: read-only directory, symlink traversal, /dev/null, long paths, overwrite behavior
- **Fuzz tests**: Go native fuzzing for workflow parser, Dockerfile parser, and all reference parsers (action, Docker, PyPI, npm). Millions of random inputs, zero panics found.

122 tests (up from 101), race detector clean, 4 fuzz targets.

## [0.1.8] - 2026-03-28

### Added
- 46 production-grade tests (101 total, up from 55):
  - **Network failure tests**: resolver timeout, 404, 500, rate limit, malformed JSON, empty response, context cancellation
  - **Parser adversarial tests**: empty files, null bytes, binary content, deeply nested YAML, malformed YAML, long image refs, control chars, build arg skip
  - **Graph correctness tests**: node creation verification, Cypher query results, secret violation detection, dedup behavior, parameter injection defense, query parsing
  - **Manifest security tests**: empty JSON, invalid JSON, truncated, binary content, wrong key, algorithm confusion, malformed base64, short keys, deterministic signing, empty lockfile, empty hash drift

### Fixed
- **Security bug found by tests**: GitHub resolver accepted empty SHA hashes without error. Now validates SHA is non-empty before returning.

## [0.1.7] - 2026-03-28

### Added
- **Docker ecosystem**: Dockerfile parser (FROM directives) + Docker Registry V2 resolver (tag -> manifest digest)
- **PyPI ecosystem**: resolver (version -> SHA256 via PyPI JSON API)
- **npm ecosystem**: resolver (version -> integrity hash via npm registry), supports scoped packages
- **OIDC keyless signing**: auto-detects OIDC tokens from GitHub Actions, GitLab CI, or generic env. Generates ephemeral ed25519 keypair, embeds OIDC issuer + subject in signature. Falls back to ed25519 if no OIDC available.
- Expanded DSM profiles from 10 to 30: added AWS configure-credentials, GCP auth, Azure login, Docker login/setup-buildx/metadata, GitHub CodeQL, Codecov, SonarCloud, HashiCorp setup-terraform, Helm chart-releaser, softprops gh-release, Slack notification, GoReleaser, peter-evans create-pull-request, actions setup-java/setup-dotnet/github-script/create-release/deploy-pages
- Documentation: `doc/oidc-signing.md` — complete guide to keyless signing
- 17 new tests (parser: 7 Dockerfile, resolver: 7 Docker/PyPI/npm, manifest: 3 OIDC)

### Changed
- Signing auto-selects: OIDC keyless in CI, ed25519 fallback locally
- Ed25519 verifier now accepts both `ed25519` and `oidc+ed25519` algorithms
- README ecosystems table updated to reflect implemented resolvers

## [0.1.6] - 2026-03-28

### Added
- `--strict` flag on check and scope: unsigned lockfiles rejected, warnings become errors
- Colored terminal output: green checkmarks, red X marks, yellow warnings (auto-detect terminal via x/term)
- Per-package unit tests: parser (4), resolver (4), manifest/lock (3), manifest/sign (5),
  manifest/drift (4), scoper (4), graph (4), cmd (10) = 38 total tests
- Race detector clean (`go test -race ./...`)

## [0.1.5] - 2026-03-28

### Added
- `scg scope` working end-to-end: parse workflow, bootstrap DSM, scan environment,
  populate graph with secret nodes, query for forbidden pattern violations
- `scg update` working: re-resolves all dependencies and rewrites lockfile
- `scg audit` working: combines drift detection + secret exposure analysis in one report
- `--json` flag on init, check, scope, audit for machine-readable output
- 3 drift simulation tests: clean check, single-tool tamper, multi-tool tamper

### Changed
- README: removed out-of-scope attacks (xz, 3CX, SolarWinds) — focus on what SCG does
- Coverage matrix cleaned up: 7 direct attacks, no indirect entries

## [0.1.4] - 2026-03-28

### Added
- `scg init` working end-to-end: discover workflows, parse GitHub Actions YAML,
  resolve tool references via GitHub API, populate TKG temporal knowledge graph,
  sign with ed25519, write `scg.lock`
- `scg check` working end-to-end: read lockfile, verify signature, re-resolve
  dependencies, detect drift, exit 0 (clean) or 1 (drift detected)
- Graph population with deduplication: same tool in multiple steps creates one
  Tool node, one Digest node, with correct USES/RESOLVES_TO/HAS_ACCESS relationships
- DSM profile linking: versioned tools (e.g., `trivy-action@v1`) linked to
  bootstrap security profiles via base reference matching
- 7 integration tests with mock resolver (no network calls)
- Sample workflow fixture (`internal/testutil/testdata/ci.yml`)
- Smoke-tested with real GitHub API (actions/checkout@v4, actions/setup-go@v5)

## [0.1.3] - 2026-03-28

### Changed
- README restructured: Quick Start moved above the fold, funnel structure (What → Install → Why → Deep dive)
- Attack tables sorted chronologically (newest first), split into "Direct" vs "Outside Scope" with honest assessments
- Removed overclaims on SolarWinds, 3CX, xz/liblzma — clearly marked as indirect/outside SCG's scope
- All URLs updated to `scg.data-insights.ai`, email to `security@data-insights.ai`
- CLAUDE.md consolidated with full package layout, exact dependency versions, session protocol

### Added
- SKILL.md for agent/tool discovery — describes CLI, library, CI, and API integration paths
- CONTRIBUTING.md for contributor onboarding

## [0.1.2] - 2026-03-28

### Added
- Comprehensive "Why SCG?" section with kill chain analysis for 9 real-world supply chain attacks:
  tj-actions/changed-files, reviewdog, Codecov, xz/liblzma, SolarWinds, ua-parser-js,
  event-stream, PyTorch dependency confusion, PyPI typosquatting campaigns
- Per-attack kill chain diagrams showing exactly where SCG breaks each attack
- Coverage matrix: digest pinning stops 9/9, secret scoping provides defense-in-depth for 3

### Changed
- Platform URL updated to `scg.data-insights.ai` (from placeholder)

## [0.1.1] - 2026-03-28

### Added
- Project scaffold with full package structure
- Graph schema: 7 node labels, 7 relationship types (temporal RESOLVES_TO)
- TKG v3 integration: in-memory (CLI) and BadgerDB (daemon) graph backends
- Cypher query engine integration for policy evaluation
- CLI skeleton with `init`, `check`, `update`, `scope`, `audit`, `version` commands
- GitHub Actions workflow parser (`.github/workflows/*.yml`)
- GitHub Actions resolver (tag/branch -> commit SHA via GitHub API)
- Ed25519 lockfile signing with verification
- Drift detection engine (compare locked vs. live digests)
- Secret scoping engine with Cypher-based policy queries
- Environment variable scanner for secret-like variables
- Embedded DSM security profiles for top 10 GitHub Actions
- `scg.lock` lockfile format (JSON, human-readable, git-diffable)
- Platform API client stubs (for future paid tier)
- Configuration via environment variables
- Comprehensive documentation: architecture, security model, getting started, lockfile spec
