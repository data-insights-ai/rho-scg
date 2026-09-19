package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/data-insights-ai/rho-scg/internal/config"
	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/platform"
	"github.com/data-insights-ai/rho-scg/resolver"
)

// doCheck validates a lockfile against live resolution.
// Signatures are always verified. No bypass.
// checkOutcome is what a check found, for --json and callers that report
// it themselves; doCheck prints it and returns only the verdict.
type checkOutcome struct {
	Results  []manifest.DriftResult
	Warnings []string
	Total    int
	Verified int
}

func doCheck(ctx context.Context, logger *slog.Logger, lockfilePath, sarifPath string) error {
	_, err := doCheckDetailed(ctx, logger, lockfilePath, sarifPath)
	return err
}

func doCheckDetailed(ctx context.Context, logger *slog.Logger, lockfilePath, sarifPath string) (checkOutcome, error) {
	var out checkOutcome
	// 1. Read lockfile.
	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		return out, fmt.Errorf("read lockfile: %w", err)
	}

	// 2. Verify the signature against the pinned platform key (mandatory, no bypass).
	//
	// The verifier is anchored to a key compiled into this binary, not to the
	// key carried inside the lockfile. Verifying against the embedded key only
	// proved that whoever wrote the file also signed it — a property any
	// attacker satisfies by generating their own keypair before opening a pull
	// request.
	if lf.Signature == nil {
		return out, fmt.Errorf("lockfile is not signed — run 'scg init' to create a signed lockfile")
	}
	if err := manifest.VerifyLockfile(lf, manifest.NewPlatformVerifier()); err != nil {
		return out, fmt.Errorf("signature verification failed: %w", err)
	}
	printSuccess(os.Stdout, "Signature verified (SCG platform key %s)",
		manifest.PlatformKeyFingerprint())

	// 3. Build resolvers for ALL ecosystems.
	resolvers := buildResolvers()

	// 4. Detect drift (continues on per-tool errors).
	results, warnings, err := detectDriftWithPartialFailure(ctx, lf, resolvers, logger)
	if err != nil {
		return out, fmt.Errorf("drift detection: %w", err)
	}
	out.Results, out.Warnings = results, warnings

	// 5. Emit SARIF before reporting, so the findings reach GitHub code
	// scanning even on the paths below that return an error.
	if sarifPath != "" {
		if err := emitSARIF(sarifPath, lockfilePath, results, warnings); err != nil {
			return out, operational("write SARIF report: %w", err)
		}
	}

	// 6. Report warnings (tools that couldn't be resolved).
	for _, w := range warnings {
		printWarning(os.Stdout, "%s", w)
	}

	// 7. Count what was actually verified vs skipped.
	totalTools := 0
	for _, p := range lf.Pipelines {
		for _, s := range p.Steps {
			totalTools += len(s.Tools)
		}
	}
	verified := totalTools - len(warnings)
	out.Total, out.Verified = totalTools, verified

	// If nothing was verified, that's a failure — not "clean".
	if verified <= 0 && totalTools > 0 {
		outln(os.Stderr)
		printFailure(os.Stderr, "No tools could be verified (%d skipped). Rate limited or platform unavailable. Try again later or set SCG_API_KEY for higher limits.", len(warnings))
		outln(os.Stderr)
		return out, operational("verification failed: 0 of %d tools checked", totalTools)
	}

	// Report results.
	if len(results) == 0 {
		outln(os.Stdout)
		if len(warnings) > 0 {
			// Partial verification is a failure for a security tool.
			// All tools must be verified — no exceptions.
			printFailure(os.Stdout, "%d of %d tools verified, %d could not be checked.", verified, totalTools, len(warnings))
			outln(os.Stdout)
			// Incomplete verification is an SCG problem, not a finding about
			// the user's dependencies: nothing was detected, we simply could
			// not look. Reporting it as a finding is what made an outage
			// indistinguishable from an attack.
			return out, operational("incomplete verification: %d of %d tools could not be checked", len(warnings), totalTools)
		}
		printSuccess(os.Stdout, "All %d tool entries verified, no drift detected.", totalTools)
		outln(os.Stdout)
		return out, nil
	}

	// Drift found.
	outf(os.Stderr, "\n  %s\n\n", red(bold("CRITICAL DRIFT DETECTED")))
	for _, d := range results {
		printFailure(os.Stderr, "%s", d.Reference)
		outf(os.Stderr, "      Locked: %s\n", dim(d.LockedHash))
		outf(os.Stderr, "      Live:   %s\n", dim(d.LiveHash))
		outf(os.Stderr, "      %s\n\n", d.Detail)
	}
	outf(os.Stderr, "  %s\n\n", red("Build HALTED. Exit code: 1"))

	return out, fmt.Errorf("drift detected: %d tool(s) changed", len(results))
}

// buildResolvers creates platform resolvers for all supported ecosystems.
// The platform IS the resolver. No GitHub token needed.
func buildResolvers() map[resolver.Ecosystem]resolver.Resolver {
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)

	return map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: platform.NewPlatformResolver(client, resolver.EcoGitHubAction),
		resolver.EcoDocker:       platform.NewPlatformResolver(client, resolver.EcoDocker),
		resolver.EcoPyPI:         platform.NewPlatformResolver(client, resolver.EcoPyPI),
		resolver.EcoNPM:          platform.NewPlatformResolver(client, resolver.EcoNPM),
	}
}

// uniqueRef identifies one distinct thing to resolve. A lockfile records a
// tool entry per step, so the same action appears once per step that uses it —
// four times for actions/checkout@v4 in this repo's own lockfile. Resolving per
// entry spent four requests to ask one question, against a budget of twenty an
// hour.
type uniqueRef struct {
	Ecosystem string
	Reference string
}

// refResult is what resolving one unique reference produced.
type refResult struct {
	resolution *resolver.Resolution
	stale      bool
	staleAge   time.Duration
	err        error
}

// maxConcurrentResolves bounds parallelism. The work is entirely network-bound,
// so some concurrency is free latency; too much just trips the rate limiter
// faster and reads as a burst to the platform.
const maxConcurrentResolves = 8

// collectUniqueRefs returns the distinct (ecosystem, reference) pairs in the
// lockfile along with how many entries each one covers.
func collectUniqueRefs(lf *manifest.Lockfile) ([]uniqueRef, map[uniqueRef]int) {
	counts := make(map[uniqueRef]int)
	var order []uniqueRef
	for _, pipeline := range lf.Pipelines {
		for _, step := range pipeline.Steps {
			for _, tool := range step.Tools {
				u := uniqueRef{Ecosystem: tool.Ecosystem, Reference: tool.Reference}
				if _, seen := counts[u]; !seen {
					order = append(order, u)
				}
				counts[u]++
			}
		}
	}
	return order, counts
}

// resolveUnique resolves every distinct reference concurrently.
func resolveUnique(
	ctx context.Context,
	refs []uniqueRef,
	resolvers map[resolver.Ecosystem]resolver.Resolver,
	log *slog.Logger,
) map[uniqueRef]refResult {
	results := make(map[uniqueRef]refResult, len(refs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentResolves)

	for _, u := range refs {
		wg.Add(1)
		go func(u uniqueRef) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				results[u] = refResult{err: ctx.Err()}
				mu.Unlock()
				return
			}

			res, ok := resolvers[resolver.Ecosystem(u.Ecosystem)]
			if !ok {
				mu.Lock()
				results[u] = refResult{err: fmt.Errorf("no resolver for ecosystem %q", u.Ecosystem)}
				mu.Unlock()
				return
			}

			if log != nil {
				log.Info("resolving", "ref", u.Reference, "ecosystem", u.Ecosystem)
			}

			out := refResult{}
			live, err := res.Resolve(ctx, u.Reference)
			if err != nil {
				out.err = err
			} else {
				out.resolution = live
				// The platform reports whether its own answer is older than the
				// freshness budget for the ecosystem. A stale digest matching a
				// stale lockfile is not evidence of anything — both sides came
				// from the same unrefreshed record — so it must not be counted
				// as verified.
				if meta, ok := res.(resolver.FreshnessReporter); ok {
					out.stale, out.staleAge = meta.Freshness(u.Reference)
				}
			}

			mu.Lock()
			results[u] = out
			mu.Unlock()
		}(u)
	}

	wg.Wait()
	return results
}

// detectDriftWithPartialFailure resolves each distinct reference once and
// compares every lockfile entry against the result. Per-reference failures
// become warnings rather than aborting the run; stale answers are reported
// separately because they are neither a pass nor a detection.
func detectDriftWithPartialFailure(
	ctx context.Context,
	lf *manifest.Lockfile,
	resolvers map[resolver.Ecosystem]resolver.Resolver,
	logger ...*slog.Logger,
) ([]manifest.DriftResult, []string, error) {
	var log *slog.Logger
	if len(logger) > 0 {
		log = logger[0]
	}

	refs, _ := collectUniqueRefs(lf)
	resolved := resolveUnique(ctx, refs, resolvers, log)

	var results []manifest.DriftResult
	var warnings []string

	for _, pipeline := range lf.Pipelines {
		for _, step := range pipeline.Steps {
			for _, tool := range step.Tools {
				u := uniqueRef{Ecosystem: tool.Ecosystem, Reference: tool.Reference}
				got := resolved[u]

				if got.err != nil {
					warnings = append(warnings, fmt.Sprintf("%s — %s", tool.Reference, rootCause(got.err)))
					continue
				}
				if got.stale {
					warnings = append(warnings, fmt.Sprintf(
						"%s — platform data is stale (last confirmed %s ago); not verified",
						tool.Reference, got.staleAge.Round(time.Minute)))
					continue
				}

				if got.resolution.Hash != tool.Hash {
					results = append(results, manifest.DriftResult{
						Ecosystem:  tool.Ecosystem,
						Reference:  tool.Reference,
						LockedHash: tool.Hash,
						LiveHash:   got.resolution.Hash,
						Severity:   manifest.SevCritical,
						Detail: fmt.Sprintf(
							"ALERT: %s resolved to different digest. "+
								"Locked: %s, Live: %s. Possible tag hijack.",
							tool.Reference,
							tool.Hash[:manifest.MinLen(len(tool.Hash), 16)],
							got.resolution.Hash[:manifest.MinLen(len(got.resolution.Hash), 16)],
						),
					})
				}
			}
		}
	}

	return results, warnings, nil
}

// rootCause unwraps to the innermost error, skipping the nested "resolve X:"
// wrapping that would otherwise dominate the message.
func rootCause(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}

// emitSARIF writes the SARIF report to path.
func emitSARIF(path, lockfilePath string, drift []manifest.DriftResult, warnings []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if err := writeSARIF(f, lockfilePath, drift, warnings); err != nil {
		return err
	}
	return f.Close()
}
