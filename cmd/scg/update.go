package main

import (
	"context"
	"log/slog"
	"os"
)

// doUpdate re-resolves all dependencies and rewrites the lockfile.
func doUpdate(ctx context.Context, logger *slog.Logger, projectRoot, workflowDir, lockfilePath string) error {
	resolvers := buildResolvers()

	outf(os.Stdout, "\n  Updating %s ...\n", lockfilePath)

	return doInit(ctx, logger, projectRoot, workflowDir, lockfilePath, resolvers, newPlatformSigner())
}
