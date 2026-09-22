# Release checklist

This release changes the trust anchor, so the order of operations matters more
than usual. Releasing the CLI before the platform breaks every user: the new
binary only accepts `ed25519-platform` signatures, and it needs a platform that
issues them and reports freshness.

Work top to bottom. Do not skip the verification step in each phase.

---

## Phase 1 — Deploy the platform

Production runs **v0.6.3**; the freshness work is in `main` and undeployed.
Until this lands, `/v1/resolve` returns no timestamp and the CLI has nothing to
judge staleness against — every answer looks fresh regardless of age.

1. Merge `hardening/freshness-observability-billing`.
2. Tag and deploy. The pipeline runs `make ci`, `golangci-lint`, `govulncheck`
   and `make cover-gate`.
3. Confirm the signing key survived the deploy. **This is the one irreversible
   check**: a new key invalidates every lockfile ever signed.

   ```sh
   curl -s https://scg.data-insights.ai/v1/pubkey
   ```

   `public_key` must still be `Z+U1HXD+1LrnVdYXDR/MhuYaEApwtN5+wYkn6VeosWU=`,
   which is the value pinned in `manifest.PlatformPublicKey`. If it differs,
   **stop** — the `/data` volume was not preserved. Restore it rather than
   shipping a CLI pinned to a key the platform no longer holds.

4. Confirm the new fields are being served:

   ```sh
   curl -s 'https://scg.data-insights.ai/v1/resolve/github_action/actions%2Fcheckout@v4'
   ```

   Expect `resolved_at`, `age_seconds`, `stale` and
   `freshness_budget_seconds`. Absent fields mean the old build is still live.

5. Watch `/v1/status` for one hour, across at least one `resolve-all` run:

   ```sh
   curl -s https://scg.data-insights.ai/v1/status
   ```

   - `resolution_healthy` should become `true` after the first sweep.
   - `freshness_healthy` will be **false at first** and that is expected: the
     corpus has never been re-confirmed, so every entry is unstamped and counts
     stale. It should climb as sweeps run.
   - Check the logs for `resolution sweep abandoned` (the budget ran out) and
     `resolution sweep is over its per-run rate budget` (raise
     `SCGD_RESOLVE_SHARDS`; the log line carries the suggested value).

### Do not proceed until

`freshness_healthy` is `true`, and the digest for `actions/checkout@v4` matches
GitHub:

```sh
curl -s 'https://scg.data-insights.ai/v1/resolve/github_action/actions%2Fcheckout@v4' | grep -o '"hash":"[^"]*"'
curl -s https://api.github.com/repos/actions/checkout/git/ref/tags/v4 | grep -o '"sha": "[^"]*"'
```

These were **different** at audit time — `34e11487…` versus `11d5960a…`. They
must agree before the CLI ships, or the first thing users get is a correct
staleness warning on the most-used action on GitHub.

---

## Phase 2 — Release the CLI

1. Merge `hardening/trust-anchor-and-freshness`.
2. Move the `[Unreleased]` block in `CHANGELOG.md` under the new version.
3. Tag a **patch** version (`v0.1.33`). Per `CLAUDE.md`, minor and major bumps
   need explicit approval — ask before deviating, even though this release
   carries breaking changes.
4. Verify the released artifact is signed:

   ```sh
   cosign verify-blob \
     --certificate checksums.txt.pem \
     --signature checksums.txt.sig \
     --certificate-identity-regexp 'https://github.com/data-insights-ai/rho-scg/.*' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     checksums.txt
   ```

5. Verify a clean install end to end, on a machine with no Go toolchain:

   ```sh
   curl -sSL https://scg.data-insights.ai/install.sh | sh
   scg version
   cd /tmp && git clone <a test repo> && cd <it>
   scg init && scg check   # expect exit 0
   ```

---

## Phase 3 — Tell users about the break

The migration is one command, but the failure message appears before anyone
reads release notes, so it has to be findable.

- Release notes lead with the breaking change and the fix: **run `scg init`
  once and commit the regenerated `scg.lock`.**
- Say plainly why: the old signatures were made with an ephemeral key that was
  discarded at signing time, so nothing could ever attest to them. `check`
  reported them as verified, which was the bug.
- Call out **exit code 2**. Pipelines that treat any non-zero exit as a
  detection will start reporting SCG outages as attacks. Fail on `1`, retry
  on `2`.
- Anyone pinning the Action must set `version:` to the new tag; `latest` is now
  refused rather than silently resolved.

---

## Phase 4 — Billing (only before charging anyone)

The integration is tested against a fake plan snapshotter. It has never met
Stripe. Until all three variables are set, the platform serves graph tiers and
behaves exactly as it does today — this phase is optional for a code release.

The three are all-or-nothing; a partial configuration stops startup rather than
accepting forged webhooks or losing dedup state on restart.

1. Provision Postgres and apply the rho-stripe repo migrations
   (`repos/postgres`), plus the idempotency store schema.
2. Create the Stripe account and sync the catalog from `billing/catalog.go`:
   `catalog.Diff` to preview, then `Apply`. Run `CheckDrift` afterwards to
   confirm nothing was edited in the dashboard behind the code.
3. Register the webhook endpoint at `POST /v1/billing/webhook` and take the
   signing secret.
4. Set, together:
   - `SCG_STRIPE_SECRET_KEY`
   - `SCG_STRIPE_WEBHOOK_SECRET`
   - `SCG_BILLING_DATABASE_URL`
   - optionally `SCG_BILLING_SUCCESS_URL`, `SCG_BILLING_CANCEL_URL`
5. Exercise it in test mode, end to end:
   - `POST /v1/billing/checkout` with `{"plan":"pro","interval":"monthly"}`,
     complete the hosted checkout.
   - `GET /v1/billing/subscription` should report `tier: pro`,
     `rate_limit_per_hour: 5000`, `source: stripe`.
   - **Cancel it.** Confirm the tier degrades to `free` at 100/hr rather than
     to zero: a lapsed subscription must degrade service, never sever it
     mid-pipeline.
   - Stop the Stripe webhook (or block egress) and confirm
     `GET /v1/billing/subscription` reports `source: cache` and keeps the paid
     limit. A billing outage must not downgrade a paying customer.

---

## Known-good post-release state

| Check | Expected |
|---|---|
| `GET /v1/pubkey` | key unchanged, `ed25519-platform` |
| `GET /v1/status` → `resolution_healthy` | `true` |
| `GET /v1/status` → `freshness_healthy` | `true` |
| `scg check` on a fresh `scg init` | exit 0, "Signature verified" |
| `scg check` against an outage | exit 2, not 1 |
| CI `dogfood` job | green |
