# Getting Started

## Installation

### Binary Release

```bash
# Linux (amd64)
curl -sSL https://scg.dev/install.sh | sh

# macOS (Apple Silicon)
curl -sSL https://scg.dev/install.sh | sh
```

### From Source

```bash
git clone https://github.com/bds421/supply-chain-guardian.git
cd supply-chain-guardian
make build
./scg version
```

Requirements: Go 1.26+

### Go Install

```bash
go install gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/cmd/scg@latest
```

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
          curl -sSL https://scg.dev/install.sh | sh
          scg check
```

If any dependency has drifted since you locked it, `scg check` exits with code 1 and your build halts.

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

## Using with GitHub Token

To avoid GitHub API rate limits, set a token:

```bash
export GITHUB_TOKEN=ghp_xxx
scg init
```

In CI, use the built-in `GITHUB_TOKEN`:

```yaml
      - name: Verify supply chain
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: scg check
```

## Full Audit

Run a comprehensive audit of your CI pipeline:

```bash
scg audit
```

This combines dependency verification and secret exposure analysis into a single report.

## Troubleshooting

### "Could not resolve ref"
- Ensure `GITHUB_TOKEN` is set for private repositories
- Check that the action reference is valid (`owner/repo@version`)

### "Lockfile is not signed"
- Run `scg update` to regenerate and sign the lockfile

### Rate limiting
- Set `GITHUB_TOKEN` to increase API rate limits from 60/hour to 5,000/hour
- Consider SCG Platform (pre-computed hashes, no rate limits)
