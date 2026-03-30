# SCG CLI — Task List

## Done

### Foundation + Commands
- [x] All 5 commands: init, check, update, scope, audit
- [x] 4 parsers: GitHub Actions YAML, Dockerfile, PyPI, npm
- [x] Lockfile: JSON format, ed25519 signing, verification
- [x] Graph: TKG integration for init/audit (scope uses platform directly)
- [x] 30 embedded DSM security profiles
- [x] 119 tests + 4 fuzz targets, race clean

### Platform-Only Architecture
- [x] `scg check` → platform `/v1/resolve` (hash verification)
- [x] `scg scope` → platform `/v1/profile` (secret scoping)
- [x] No local resolvers. No GITHUB_TOKEN. No fallback.
- [x] Platform client works without API key (20/hr anonymous)
- [x] Response caching (5 min TTL)

### Distribution
- [x] Install script: scg.bds421.com/install.sh
- [x] Cross-compiled binaries: linux/darwin amd64/arm64
- [x] GitHub Action wrapper: action.yml
- [x] Landing page: scg.bds421.com with Data Insights AI branding

## Current

- [ ] Full end-to-end test on a real repo (init → check → scope)
- [ ] Integration test: detect PYPI_TOKEN violation via platform profile

## Next

- [ ] CI pipeline: auto-build + upload on tag push (eliminate manual scp)
- [ ] GitHub Action published to GitHub Marketplace
- [ ] Homebrew tap formula
