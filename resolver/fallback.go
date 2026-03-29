package resolver

import (
	"context"
	"log/slog"
)

// FallbackResolver tries the primary resolver first, falls back to
// the secondary on any error. Used to try the platform first, then
// local resolution if the platform is unavailable or rate-limited.
type FallbackResolver struct {
	primary   Resolver
	fallback  Resolver
	ecosystem Ecosystem
	logger    *slog.Logger
}

// NewFallbackResolver creates a resolver that tries primary first, then fallback.
func NewFallbackResolver(primary, fallback Resolver, eco Ecosystem, logger *slog.Logger) *FallbackResolver {
	return &FallbackResolver{
		primary:   primary,
		fallback:  fallback,
		ecosystem: eco,
		logger:    logger,
	}
}

// Ecosystem returns which ecosystem this resolver handles.
func (r *FallbackResolver) Ecosystem() Ecosystem {
	return r.ecosystem
}

// Resolve tries the primary resolver. If it fails, falls back to the secondary.
func (r *FallbackResolver) Resolve(ctx context.Context, reference string) (*Resolution, error) {
	res, err := r.primary.Resolve(ctx, reference)
	if err == nil {
		return res, nil
	}

	// Primary failed — fall back silently in non-verbose mode.
	if r.logger != nil {
		r.logger.Info("platform unavailable, falling back to local", "ref", reference, "err", err)
	}

	return r.fallback.Resolve(ctx, reference)
}
