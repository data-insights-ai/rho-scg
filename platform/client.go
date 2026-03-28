// Package platform provides the client for the SCG Platform API.
// The platform provides pre-computed hashes, curated security profiles,
// drift alerts, and temporal history — available with a subscription.
package platform

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ErrNotConfigured indicates no platform API key is set.
var ErrNotConfigured = errors.New("SCG platform not configured: set SCG_API_KEY for access to pre-computed hashes and curated profiles")

// Client is the SCG Platform API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new Platform API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IsConfigured reports whether the platform API key is set.
func (c *Client) IsConfigured() bool {
	return c.apiKey != ""
}

// Resolve fetches a pre-computed resolution from the platform.
func (c *Client) Resolve(ctx context.Context, ecosystem, reference string) (*ResolveResponse, error) {
	if !c.IsConfigured() {
		return nil, ErrNotConfigured
	}

	// TODO: implement platform API call
	return nil, ErrNotConfigured
}

// FetchProfile fetches a curated security profile from the platform.
func (c *Client) FetchProfile(ctx context.Context, ecosystem, reference string) (*ProfileResponse, error) {
	if !c.IsConfigured() {
		return nil, ErrNotConfigured
	}

	// TODO: implement platform API call
	return nil, ErrNotConfigured
}
