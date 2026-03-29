package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/manifest"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
)

// doCheck validates a lockfile against live resolution.
// Signatures are required by default. Use --no-verify to skip (not recommended).
func doCheck(ctx context.Context, logger *slog.Logger, lockfilePath, ghToken string, noVerify bool) error {
	// 1. Read lockfile.
	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		return fmt.Errorf("read lockfile: %w", err)
	}

	// 2. Verify signature (mandatory by default).
	if noVerify {
		printWarning(os.Stdout, "Signature verification skipped (--no-verify)")
	} else if lf.Signature != nil {
		if err := manifest.VerifyLockfile(lf, &manifest.Ed25519Verifier{}); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
		printSuccess(os.Stdout, "Signature verified")
	} else {
		return fmt.Errorf("lockfile is not signed — run 'scg init' to sign it, or use --no-verify to skip (not recommended)")
	}

	// 3. Build resolvers for ALL ecosystems.
	resolvers := buildResolvers(ghToken)

	// 4. Detect drift (continues on per-tool errors).
	results, warnings, err := detectDriftWithPartialFailure(ctx, lf, resolvers)
	if err != nil {
		return fmt.Errorf("drift detection: %w", err)
	}

	// 5. Report warnings (tools that couldn't be resolved).
	for _, w := range warnings {
		printWarning(os.Stdout, "%s", w)
	}

	// 6. Report results.
	if len(results) == 0 {
		totalTools := 0
		for _, p := range lf.Pipelines {
			for _, s := range p.Steps {
				totalTools += len(s.Tools)
			}
		}
		fmt.Fprintln(os.Stdout)
		printSuccess(os.Stdout, "All %d tool entries verified, no drift detected.", totalTools)
		fmt.Fprintln(os.Stdout)
		return nil
	}

	// Drift found.
	fmt.Fprintf(os.Stderr, "\n  %s\n\n", red(bold("CRITICAL DRIFT DETECTED")))
	for _, d := range results {
		printFailure(os.Stderr, "%s", d.Reference)
		fmt.Fprintf(os.Stderr, "      Locked: %s\n", dim(d.LockedHash))
		fmt.Fprintf(os.Stderr, "      Live:   %s\n", dim(d.LiveHash))
		fmt.Fprintf(os.Stderr, "      %s\n\n", d.Detail)
	}
	fmt.Fprintf(os.Stderr, "  %s\n\n", red("Build HALTED. Exit code: 1"))

	return fmt.Errorf("drift detected: %d tool(s) changed", len(results))
}

// buildResolvers creates resolvers for all supported ecosystems.
func buildResolvers(ghToken string) map[resolver.Ecosystem]resolver.Resolver {
	return map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: resolver.NewGitHubResolver(ghToken),
		resolver.EcoDocker:       resolver.NewDockerResolver(),
		resolver.EcoPyPI:         resolver.NewPyPIResolver(),
		resolver.EcoNPM:          resolver.NewNPMResolver(),
	}
}

// detectDriftWithPartialFailure runs drift detection but continues
// on per-tool resolution errors instead of failing the entire check.
// Returns drift results + warnings for tools that couldn't be resolved.
func detectDriftWithPartialFailure(ctx context.Context, lf *manifest.Lockfile, resolvers map[resolver.Ecosystem]resolver.Resolver) ([]manifest.DriftResult, []string, error) {
	var results []manifest.DriftResult
	var warnings []string

	for _, pipeline := range lf.Pipelines {
		for _, step := range pipeline.Steps {
			for _, tool := range step.Tools {
				eco := resolver.Ecosystem(tool.Ecosystem)
				res, ok := resolvers[eco]
				if !ok {
					warnings = append(warnings, fmt.Sprintf("no resolver for ecosystem %q — %s not checked", tool.Ecosystem, tool.Reference))
					continue
				}

				live, err := res.Resolve(ctx, tool.Reference)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("could not resolve %s: %v — skipped", tool.Reference, err))
					continue
				}

				if live.Hash != tool.Hash {
					results = append(results, manifest.DriftResult{
						Ecosystem:  tool.Ecosystem,
						Reference:  tool.Reference,
						LockedHash: tool.Hash,
						LiveHash:   live.Hash,
						Severity:   manifest.SevCritical,
						Detail: fmt.Sprintf(
							"ALERT: %s resolved to different digest. "+
								"Locked: %s, Live: %s. Possible tag hijack.",
							tool.Reference,
							tool.Hash[:manifest.MinLen(len(tool.Hash), 16)],
							live.Hash[:manifest.MinLen(len(live.Hash), 16)],
						),
					})
				}
			}
		}
	}

	return results, warnings, nil
}
