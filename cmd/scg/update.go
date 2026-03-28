package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
)

// doUpdate re-resolves all dependencies and rewrites the lockfile.
// This is essentially scg init that overwrites an existing lockfile.
func doUpdate(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string) error {
	ghToken := os.Getenv("GITHUB_TOKEN")
	res := resolver.NewGitHubResolver(ghToken)

	fmt.Fprintf(os.Stdout, "\n  Updating %s ...\n", lockfilePath)

	return doInit(ctx, logger, workflowDir, lockfilePath, res)
}
