package platform

import (
	"context"
	"sync"
	"time"

	"github.com/data-insights-ai/rho-scg/resolver"
)

// PlatformResolver uses the SCG Platform API for resolution instead of
// calling registries directly. Faster (pre-computed), no rate limits.
type PlatformResolver struct {
	client    *Client
	ecosystem resolver.Ecosystem

	// freshness records what the platform said about the age of each answer,
	// so callers can refuse to treat a stale digest as a verified one.
	mu        sync.Mutex
	freshness map[string]freshnessInfo
}

type freshnessInfo struct {
	stale bool
	age   time.Duration
}

// NewPlatformResolver creates a resolver backed by the platform API.
func NewPlatformResolver(client *Client, eco resolver.Ecosystem) *PlatformResolver {
	return &PlatformResolver{
		client:    client,
		ecosystem: eco,
		freshness: make(map[string]freshnessInfo),
	}
}

// Freshness reports whether the platform's answer for reference was stale.
func (r *PlatformResolver) Freshness(reference string) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	info := r.freshness[reference]
	return info.stale, info.age
}

// Ecosystem returns which ecosystem this resolver handles.
func (r *PlatformResolver) Ecosystem() resolver.Ecosystem {
	return r.ecosystem
}

// Resolve fetches a pre-computed digest from the platform.
func (r *PlatformResolver) Resolve(ctx context.Context, reference string) (*resolver.Resolution, error) {
	resp, err := r.client.Resolve(ctx, string(r.ecosystem), reference)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.freshness[reference] = freshnessInfo{
		stale: resp.Stale,
		age:   time.Duration(resp.AgeSeconds) * time.Second,
	}
	r.mu.Unlock()

	// ResolvedAt is the platform's own last confirmation, not the moment we
	// asked. Stamping time.Now() here would have made every answer look fresh
	// regardless of how old the underlying data was.
	resolvedAt := resp.ResolvedAt
	if resolvedAt.IsZero() {
		resolvedAt = time.Now()
	}

	return &resolver.Resolution{
		Original:   reference,
		Hash:       resp.Hash,
		Algorithm:  resp.Algorithm,
		Canonical:  reference + "@" + resp.Hash,
		Source:     "platform:" + resp.Source,
		ResolvedAt: resolvedAt,
	}, nil
}
