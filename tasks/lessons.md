# Lessons

Patterns worth not relearning. Each one came from a defect that was live in
production or in `main`.

## A verifier that reads both sides from the same source verifies nothing

`scg init` wrote the lockfile from the platform's record, and `scg check`
compared it against the platform's record. As long as that record was stale in
a stable way, every run was green and nothing was checked. Two of the four
references in this repo's own lockfile were wrong at the time.

The tell: a system that can only ever agree with itself. Unit tests do not catch
it, because they mock the same source on both sides. Catching it needs a
differential test against ground truth — compare the platform's answer for the
top actions to `api.github.com` and alert on divergence.

## Freshness needs its own timestamp, and it is not "first seen"

The graph recorded when a digest first appeared, never when it was last
re-confirmed. A tag that has not moved in six months looked identical to one
nobody had checked in six months. `ReconcileResolutionLocked` now stamps
`last_confirmed_at` on the unchanged path too — the path that previously
returned early having learned the most useful fact and written none of it down.

## A signature anchored to a key inside the signed file is not a signature

`Ed25519Verifier` read the public key out of the lockfile and checked the
signature against it. That proves whoever wrote the file also signed it, which
every attacker satisfies by generating a keypair. Worse, the local fallback
minted an ephemeral key, signed, and discarded the private half — so nobody
could ever attest to it, and `check` printed "Signature verified" anyway.

The anchor must be something the attacker cannot choose: a key compiled into
the binary. And build-time only, never an environment variable — the threat
model includes an attacker who can edit the workflow that sets the variable.

## Never fall back to a weaker guarantee to keep working

Both fallbacks in this codebase were failures dressed as resilience:

- `signLocal` produced an unverifiable lockfile when the platform was down.
- `MatchSecrets` skipped forbidden-secret patterns that failed to compile.

Each kept the command exiting zero while silently removing the property the
command exists to provide. If the guarantee cannot be delivered, fail.

## Distinguish "we found something" from "we could not look"

Drift and a platform outage both exited 1. With no local fallback by design,
an SCG outage turned every customer's pipeline red in a way indistinguishable
from an attack. Exit 2 (`OperationalError`) now says: nothing was detected,
retry. The same distinction runs through SARIF (error vs warning) and the
billing grace period.

## An ignored error return can hide a defect for months

`errcheck` looked like lint pedantry until three discarded `CreateProperty`
returns turned out to mean two graph indexes had **never existed** — the tiered
store only indexes reference labels, and `Digest.hash` is an event label. Every
digest lookup had been unindexed since the schema was written.

## Nil checks in the composition root fail silently

`if sched := appcron.Scheduler(infra); sched != nil { ... }` with no else. If
cron were unavailable, all five jobs would never run, the service would still
report healthy, and the only symptom would be data that quietly stopped moving.

`cmd/scgd` sat at 2% coverage — composition roots are where subsystems go
missing, and the one place unit tests never look. Extract the wiring into a
testable function and assert the full set is registered.

Related Go trap: `appcron.Scheduler` returns a concrete pointer, so assigning a
nil result to an interface produces a **non-nil interface holding a nil
pointer**. `sched == nil` passes and `Add` panics. See `isNilScheduler`.

## Declared and never assigned is worse than absent

`last_resolution` was on the status response struct, marked `omitempty`, and
assigned nowhere. It marshalled as empty, `omitempty` hid it, and the endpoint
looked fine. The field that would have revealed the staleness was a no-op.

## Budgets are shared; counters must be too

`ThrottleGitHub` was declared and only ever instantiated by the crawler. The
resolve sweep called the same API, on the same token, with no counter at all.
Two private counters over one budget is arithmetically the same as none.

## Deduplicate before spending a budget

`check` walked pipelines → steps → tools and resolved every entry, so one action
used in four steps cost four of the twenty requests an anonymous user gets per
hour. Half this repo's budget was spent asking the same question.

## Tests must not reach the network

Removing the local signing fallback made `doInit` call the live platform in
tests; the suite went from 0.4s to a 120s timeout. The fix is injection
(`LockfileSigner`), not a fallback. A fallback that exists to keep tests passing
will also fire in production.

## Verify over what was signed, not a re-derivation

Verification re-marshalled the parsed struct, so anything in the file that did
not map to a struct field was invisible to the signature. `DisallowUnknownFields`
closes it: nothing can be present that the signature did not cover.

Related: `signViaPlat` had grown its own copy of the canonicalisation, next to a
comment saying `canonicalJSON` must be the only such path. They agreed by
coincidence, and the first added field would have invalidated every
platform-signed lockfile in the field.

## Substring matching is not word matching

`LooksLikeSecret` flagged `MONKEY`, `DONKEY`, `KEYBOARD` (contain "KEY"),
`AUTHOR` ("AUTH"), and `AWS_REGION`. An audit that cries wolf on ordinary
variables is one people learn to skip — a false positive rate is a security
property.

## Interpolating inputs into a shell script is code execution

`action.yml` put `${{ inputs.step-name }}` directly into a `run:` body. GitHub
substitutes before bash parses, so a value from an issue title or a matrix entry
becomes a command. Pass inputs through `env:` and quote them; build argv as an
array, not a string.

## An installer that fails open is the attack it prevents

`install.sh` warned and installed anyway when the checksum file could not be
fetched or no sha256 tool was present — so the easiest route to installing an
unverified binary was to break verification. The GitHub Action did not verify at
all.

## Do not let a provider outage become a customer verdict

The billing entitlement cache is the same lesson in a third place: if Stripe is
unreachable, serving the last known good entitlement for 24 hours is far cheaper
than dropping a paying customer to the free tier because of our outage.

## Check cross-repo coupling before deleting "dead" code

`rho-scg/resolver/{github,docker,npm,pypi}.go` looked dead — nothing in `cmd/`
used it, and it dragged the package to 42% coverage. The platform imported it in
ten files. Deleting it would have broken the backend build. It was moved, not
removed.
