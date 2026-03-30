package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/data-insights-ai/rho-scg/resolver"
)

// doUpdate re-resolves all dependencies and rewrites the lockfile.
func doUpdate(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string) error {
	res := platformResolver(resolver.EcoGitHubAction)

	fmt.Fprintf(os.Stdout, "\n  Updating %s ...\n", lockfilePath)

	return doInit(ctx, logger, workflowDir, lockfilePath, res)
}
