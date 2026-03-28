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
func doCheck(ctx context.Context, logger *slog.Logger, lockfilePath, ghToken string) error {
	// 1. Read lockfile.
	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		return fmt.Errorf("read lockfile: %w", err)
	}
	logger.Info("loaded lockfile", "path", lockfilePath, "version", lf.Version)

	// 2. Verify signature (skip if unsigned).
	if lf.Signature != nil {
		if err := manifest.VerifyLockfile(lf, &manifest.Ed25519Verifier{}); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
		logger.Info("signature verified")
	} else {
		logger.Warn("lockfile is not signed")
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
		fmt.Fprintf(os.Stdout, "\n  scg check: all %d tool entries verified, no drift detected.\n\n", totalTools)
		return nil
	}

	// Drift found — report and return error (exit 1).
	fmt.Fprintf(os.Stderr, "\n  CRITICAL DRIFT DETECTED\n\n")
	for _, d := range results {
		fmt.Fprintf(os.Stderr, "  %s\n", d.Reference)
		fmt.Fprintf(os.Stderr, "    Locked:  %s\n", d.LockedHash)
		fmt.Fprintf(os.Stderr, "    Live:    %s\n", d.LiveHash)
		fmt.Fprintf(os.Stderr, "    Status:  %s\n", d.Detail)
		fmt.Fprintf(os.Stderr, "\n")
	}
	fmt.Fprintf(os.Stderr, "  Build HALTED. Exit code: 1\n\n")

	return fmt.Errorf("drift detected: %d tool(s) changed", len(results))
}
