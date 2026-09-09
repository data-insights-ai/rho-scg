package main

import (
	"context"
	"log/slog"
	"os"
)

// doUpdate re-resolves all dependencies and rewrites the lockfile.
func doUpdate(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string) error {
	resolvers := buildResolvers()

	outf(os.Stdout, "\n  Updating %s ...\n", lockfilePath)

	return doInit(ctx, logger, workflowDir, lockfilePath, resolvers, newPlatformSigner())
}
