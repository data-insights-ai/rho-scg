# Release checklist

For a release of this CLI. Work top to bottom.

This file used to be a plan for one particular release — the trust-anchor
change of v0.1.33 — left behind as if it were the process. By the time
anybody read it again it was telling them to deploy work that had shipped
weeks earlier and to provision Stripe, which this product does not use.
Keep it general, or delete it.

---

## Before tagging

1. **CI is green on `main`.** Not "the PR was green" — `main`, after the
   merge. Four releases once went out over a red pipeline because nobody
   looked at the repository the failure was in.

2. **The platform is already deployed.** The CLI talks to
   `https://scg.data-insights.ai/v1`. If the release depends on a platform
   change, that change is live first, or the first thing users meet is a
   feature that is not there.

3. **The signing key is unchanged.** This is the one irreversible check:

   ```sh
   curl -s https://scg.data-insights.ai/v1/pubkey
   ```

   `public_key` must equal `manifest.PlatformPublicKey`. If it differs, the
   platform's `/data` volume was lost and a new key was silently generated;
   every lockfile ever signed now fails to verify. Stop and restore it
   rather than shipping a CLI pinned to a key the platform no longer holds.

4. **`CHANGELOG.md`**: move the `[Unreleased]` block under the new version
   with today's date.

5. **Version bump size.** Per `CLAUDE.md`, minor and major bumps need
   explicit approval; patch releases do not. Ask before deviating.

---

## Tagging

```sh
git tag -a vX.Y.Z -m "…"   # the message is the release note
git push origin vX.Y.Z
```

`release.yml` builds the four platform binaries, writes `checksums.txt` and
signs it with cosign keyless (the workflow's OIDC identity is the
signature).

The repository asks for pull requests on `main`. A release commit that
touches only the changelog is still a commit — push it as a PR unless you
have been told otherwise, rather than using admin rights to bypass the
required checks.

---

## After tagging

1. **The release verifies.** The server does this itself on the next
   `sync-releases.sh` run, and refuses to publish a release whose signature
   does not check out. To confirm by hand:

   ```sh
   cosign verify-blob \
     --certificate checksums.txt.pem \
     --signature checksums.txt.sig \
     --certificate-identity-regexp 'https://github.com/data-insights-ai/rho-scg/.*' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     checksums.txt
   ```

2. **The mirror has it.** Within five minutes (cron), or force it:

   ```sh
   curl -s https://scg.data-insights.ai/releases/latest/version   # expect vX.Y.Z
   ```

3. **A clean install works**, on a machine with no Go toolchain:

   ```sh
   curl -sSL https://scg.data-insights.ai/install.sh | sh
   scg version
   cd /tmp && git clone <a test repo> && cd <it>
   scg init && scg check    # expect exit 0, "Signature verified"
   ```

4. **The dogfood canary is green.** It runs every six hours and is the only
   thing that exercises the released binary against the live platform.

---

## Known-good post-release state

| Check | Expected |
|---|---|
| `GET /v1/pubkey` | key unchanged, `ed25519-platform` |
| `GET /v1/status` → `resolution_healthy` | `true` |
| `GET /v1/status` → `freshness_healthy` | `true` |
| `releases/latest/version` | the new tag |
| `scg check` on a fresh `scg init` | exit 0, "Signature verified" |
| `scg check` against a platform outage | exit 2, not 1 |
| CI `dogfood` job | green |

Exit codes matter to callers: fail the pipeline on `1` (drift or a real
finding), retry on `2` (the platform could not answer). A pipeline that
treats any non-zero exit as a detection reports SCG outages as attacks.
