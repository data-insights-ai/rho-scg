# Getting Started

## Installation

### Binary Release

```bash
# Linux (amd64)
curl -sSL https://scg.data-insights.ai/install.sh | sh

# macOS (Apple Silicon)
curl -sSL https://scg.data-insights.ai/install.sh | sh
```

### From Source

```bash
git clone https://github.com/data-insights-ai/rho-scg.git
cd supply-chain-guardian
make build
./scg version
```

Requirements: Go 1.26+

## First Run

### 1. Initialize your lockfile

Navigate to your repository root (where `.github/workflows/` lives):

```bash
cd your-project
scg init
```

SCG scans your workflow files, resolves every dependency to an immutable digest, and writes `scg.lock`.

### 2. Review and commit

```bash
# Review what was found
cat scg.lock

# Commit the lockfile
git add scg.lock
git commit -m "Add supply chain lockfile"
```

The `scg.lock` file should be committed to your repository. It's the source of truth for what your CI pipeline should be running.

### 3. Add to CI

Add `scg check` as the first step in your CI pipeline:

```yaml
# .github/workflows/ci.yml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify supply chain
        run: |
          curl -sSL https://scg.data-insights.ai/install.sh | sh
          scg check
```

If any dependency has drifted since you locked it, `scg check` exits with code 1 and your build halts. Exit code 2 means SCG could not complete the check (platform unreachable or its data too old to trust): retry, it says nothing about your dependencies.

### 4. Scope secrets (optional but recommended)

For steps that run third-party actions, add secret scoping:

```yaml
      - name: Scope secrets for Trivy
        run: scg scope --step trivy-scan

      - uses: aquasecurity/trivy-action@v1
        # Trivy now runs without PYPI_API_TOKEN in its environment
```

## Updating Dependencies

When you intentionally update a dependency:

```bash
# Re-resolve all dependencies and update the lockfile
scg update

# Review the changes
git diff scg.lock

# Commit
git add scg.lock
git commit -m "Update dependency digests"
```

## Full Audit

Run a comprehensive audit of your CI pipeline:

```bash
scg audit
```

This combines dependency verification and secret exposure analysis into a single report. Run it in CI where secrets are injected for accurate results.

## Troubleshooting

### "tool not found"
The tool hasn't been indexed by the platform yet. The crawler indexes tools with 100+ stars from known organizations.

### "Lockfile is not signed"
Run `scg init` to regenerate and sign the lockfile.

### Rate limiting
Anonymous access: 20 requests/hour. Run `scg login` or set `SCG_API_KEY` to use your organization's limit (100/hour on Free, 5,000 on Pro, 50,000 on Enterprise, shared by all keys of the organization).
