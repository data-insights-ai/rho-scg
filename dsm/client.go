package dsm

import (
	"context"
	"errors"
)

// ErrPlatformNotAvailable indicates the DSM platform API is not configured.
var ErrPlatformNotAvailable = errors.New("DSM platform not available: set SCG_API_KEY for access")

// PlatformClient fetches security profiles from the SCG platform API.
type PlatformClient struct {
	baseURL string
	apiKey  string
}

// NewPlatformClient creates a new DSM platform client.
func NewPlatformClient(baseURL, apiKey string) *PlatformClient {
	return &PlatformClient{
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

// FetchProfile fetches a security profile from the platform.
func (c *PlatformClient) FetchProfile(ctx context.Context, ecosystem, reference string) (*ProfileDef, error) {
	if c.apiKey == "" {
		return nil, ErrPlatformNotAvailable
	}

	// TODO: implement platform API call
	return nil, ErrPlatformNotAvailable
}
