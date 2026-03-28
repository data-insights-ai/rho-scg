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
func doCheck(ctx context.Context, logger *slog.Logger, lockfilePath, ghToken string, strict bool) error {
	// 1. Read lockfile.
	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		return fmt.Errorf("read lockfile: %w", err)
	}

	// 2. Verify signature (skip if unsigned).
	if lf.Signature != nil {
		if err := manifest.VerifyLockfile(lf, &manifest.Ed25519Verifier{}); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
		printSuccess(os.Stdout, "Signature verified")
	} else {
		if strict {
			return fmt.Errorf("lockfile is not signed (--strict requires signed lockfile)")
		}
		printWarning(os.Stdout, "Lockfile is not signed")
	}

	// 3. Build resolvers.
	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: resolver.NewGitHubResolver(ghToken),
	}

	// 4. Detect drift.
	results, err := manifest.DetectDrift(ctx, lf, resolvers)
	if err != nil {
		return fmt.Errorf("drift detection: %w", err)
	}

	// 5. Report results.
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
