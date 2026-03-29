package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
)

// doUpdate re-resolves all dependencies and rewrites the lockfile.
func doUpdate(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string) error {
	res := platformResolver(resolver.EcoGitHubAction)

	fmt.Fprintf(os.Stdout, "\n  Updating %s ...\n", lockfilePath)

	return doInit(ctx, logger, workflowDir, lockfilePath, res)
}
