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
	// Selection is what the project declares that the baseline does not
	// record, and the reverse. A baseline that no longer describes the
	// project is not a baseline, however well its own entries verify.
	Selection []selectionChange
}

func doCheck(ctx context.Context, logger *slog.Logger, projectRoot, workflowDir, lockfilePath, sarifPath string) error {
	_, err := doCheckDetailed(ctx, logger, projectRoot, workflowDir, lockfilePath, sarifPath)
	return err
}

func doCheckDetailed(ctx context.Context, logger *slog.Logger, projectRoot, workflowDir, lockfilePath, sarifPath string) (checkOutcome, error) {
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

	// 4. Compare what the project declares now with what was reviewed.
	//
	// Drift iterates the baseline, so a dependency added after the baseline
	// was written never reaches it. This comparison is the one that notices.
	declared, selErr := declaredDependencies(projectRoot, workflowDir)
	switch {
	case selErr != nil:
		printWarning(os.Stdout, "project files could not be read (%v); only the recorded entries were checked", selErr)
	case len(declared) == 0:
		printWarning(os.Stdout, "no project files found from here; only the recorded entries were checked")
	default:
		out.Selection = compareSelection(declared, lf)
	}

	// 5. Detect drift (continues on per-tool errors).
	results, warnings, err := detectDriftWithPartialFailure(ctx, lf, resolvers, logger)
	if err != nil {
		return out, fmt.Errorf("drift detection: %w", err)
	}
	out.Results, out.Warnings = results, warnings

	// 6. Emit SARIF before reporting, so the findings reach GitHub code
	// scanning even on the paths below that return an error.
	if sarifPath != "" {
		if err := emitSARIF(sarifPath, lockfilePath, results, warnings); err != nil {
			return out, operational("write SARIF report: %w", err)
		}
	}

	// 7. Report warnings (tools that couldn't be resolved).
	for _, w := range warnings {
		printWarning(os.Stdout, "%s", w)
	}

	// 8. Count what was actually verified vs skipped.
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

	// A baseline that no longer matches the project is reported before
	// drift: comparing yesterday's entries says nothing about a dependency
	// added today.
	if len(out.Selection) > 0 {
		printSelectionChanges(os.Stderr, out.Selection)
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
		if len(out.Selection) > 0 {
			return out, fmt.Errorf("%d dependency change(s) outside the reviewed baseline", len(out.Selection))
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

	// One request per ecosystem for the whole lockfile, so a CI run costs
	// one call against the rate limit instead of one per tool. The
	// per-reference calls below are then answered from the cache.
	prefetch(ctx, refs, resolvers, log)

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

// prefetcher is a resolver that can answer many references in one call.
type prefetcher interface {
	Prefetch(ctx context.Context, references []string) error
}

func prefetch(ctx context.Context, refs []uniqueRef, resolvers map[resolver.Ecosystem]resolver.Resolver, log *slog.Logger) {
	byEco := map[resolver.Ecosystem][]string{}
	for _, u := range refs {
		byEco[resolver.Ecosystem(u.Ecosystem)] = append(byEco[resolver.Ecosystem(u.Ecosystem)], u.Reference)
	}
	for eco, list := range byEco {
		p, ok := resolvers[eco].(prefetcher)
		if !ok || len(list) < 2 {
			continue
		}
		if err := p.Prefetch(ctx, list); err != nil && log != nil {
			log.Info("batch resolve unavailable; resolving one by one", "ecosystem", eco, "err", err)
		}
	}
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

// printSelectionChanges reports dependencies the project declares that the
// baseline never recorded, and recorded entries the project dropped.
func printSelectionChanges(w *os.File, changes []selectionChange) {
	outf(w, "\n  %s\n\n", red(bold("DEPENDENCIES OUTSIDE THE REVIEWED BASELINE")))
	for _, c := range changes {
		switch c.Kind {
		case "added":
			printFailure(w, "not in the baseline: %s (%s)", c.Reference, c.Ecosystem)
			if c.Where != "" {
				outf(w, "      Declared in: %s\n", dim(c.Where))
			}
		default:
			printWarning(w, "no longer declared: %s (%s)", c.Reference, c.Ecosystem)
		}
	}
	outf(w, "\n  %s\n\n", dim("Review the change, then record it deliberately with 'scg update'."))
}
