package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// doUpdate re-resolves all dependencies and rewrites the lockfile.
func doUpdate(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string) error {
	resolvers := buildResolvers()

	fmt.Fprintf(os.Stdout, "\n  Updating %s ...\n", lockfilePath)

	return doInit(ctx, logger, workflowDir, lockfilePath, resolvers)
}
