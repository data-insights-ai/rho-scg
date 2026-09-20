# Contributing to Supply Chain Guardian

Thank you for your interest in making CI/CD pipelines safer.

## Getting Started

```bash
git clone https://github.com/data-insights-ai/rho-scg.git
cd rho-scg
make check   # build + test + vet
```

Requirements: Go 1.26+

## Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/docker-resolver`)
3. Write tests first (TDD)
4. Implement the feature
5. Run `make ci` (must pass)
6. Submit a pull request

## Code Standards

- **Tests first.** Write the failing test, then implement. Coverage gate: 80% per package.
- **Security first.** Every input is untrusted. Parameterize queries. No secrets in logs.
- **Simple first.** Solve the actual problem. No speculative abstractions.
- **Files under 500 lines.** Split when a file grows beyond this.

## Priority Contributions

### New Ecosystem Support
Adding a new ecosystem (e.g., Docker, PyPI) requires:
1. A **parser** in `parser/` that extracts references from config files
2. A **resolver** in `resolver/` that resolves references to digests
3. Tests for both
4. An entry in the ecosystem table in README.md

### Security Profiles
Contributing a DSM profile for a CI/CD tool:
1. Security profiles are managed on the SCG Platform. Open an issue at https://github.com/data-insights-ai/rho-scg/issues describing the tool, its required secrets, and forbidden patterns with reasons.

### Bug Reports
Include:
- SCG version (`scg version`)
- OS and architecture
- Minimal reproduction steps
- Expected vs. actual behavior

## Code of Conduct

Be respectful, constructive, and focused on making software supply chains safer for everyone.
