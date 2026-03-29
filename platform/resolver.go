package platform

import (
	"context"
	"time"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
)

// PlatformResolver uses the SCG Platform API for resolution instead of
// calling registries directly. Faster (pre-computed), no rate limits.
type PlatformResolver struct {
	client    *Client
	ecosystem resolver.Ecosystem
}

// NewPlatformResolver creates a resolver backed by the platform API.
func NewPlatformResolver(client *Client, eco resolver.Ecosystem) *PlatformResolver {
	return &PlatformResolver{client: client, ecosystem: eco}
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

	return &resolver.Resolution{
		Original:   reference,
		Hash:       resp.Hash,
		Algorithm:  resp.Algorithm,
		Canonical:  reference + "@" + resp.Hash,
		Source:     "platform:" + resp.Source,
		ResolvedAt: time.Now(),
	}, nil
}
