// Package platform provides the client for the SCG Platform API.
// The platform provides pre-computed hashes, curated security profiles,
// drift alerts, and temporal history — available with a subscription.
package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ErrNotConfigured indicates no platform API key is set.
var ErrNotConfigured = errors.New("SCG platform not configured: set SCG_API_KEY for access to pre-computed hashes and curated profiles")

const maxResponseBytes = 10 * 1024 * 1024 // 10MB

// Client is the SCG Platform API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client

	// In-memory cache (5 min TTL).
	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	data      any
	expiresAt time.Time
}

const cacheTTL = 5 * time.Minute

// NewClient creates a new Platform API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: make(map[string]*cacheEntry),
	}
}

// IsConfigured reports whether the platform API key is set.
func (c *Client) IsConfigured() bool {
	return c.apiKey != ""
}

// Resolve fetches a pre-computed resolution from the platform.
func (c *Client) Resolve(ctx context.Context, ecosystem, reference string) (*ResolveResponse, error) {
	cacheKey := "resolve:" + ecosystem + ":" + reference
	if cached := c.getCache(cacheKey); cached != nil {
		return cached.(*ResolveResponse), nil
	}

	path := fmt.Sprintf("/v1/resolve/%s/%s", url.PathEscape(ecosystem), url.PathEscape(reference))
	var resp ResolveResponse
	if err := c.get(ctx, path, &resp); err != nil {
		return nil, err
	}

	c.setCache(cacheKey, &resp)
	return &resp, nil
}

// FetchProfile fetches a curated security profile from the platform.
func (c *Client) FetchProfile(ctx context.Context, ecosystem, reference string) (*ProfileResponse, error) {
	cacheKey := "profile:" + ecosystem + ":" + reference
	if cached := c.getCache(cacheKey); cached != nil {
		return cached.(*ProfileResponse), nil
	}

	path := fmt.Sprintf("/v1/profile/%s/%s", url.PathEscape(ecosystem), url.PathEscape(reference))
	var resp ProfileResponse
	if err := c.get(ctx, path, &resp); err != nil {
		return nil, err
	}

	c.setCache(cacheKey, &resp)
	return &resp, nil
}

// Sign sends content to the platform for signing with its persistent key.
func (c *Client) Sign(ctx context.Context, data []byte) (*SignResponse, error) {
	var resp SignResponse
	if err := c.post(ctx, "/v1/sign", data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Check uploads a lockfile and returns drift results from the platform.
func (c *Client) Check(ctx context.Context, lockfileJSON []byte) (*CheckResponse, error) {
	if !c.IsConfigured() {
		return nil, ErrNotConfigured
	}

	var resp CheckResponse
	if err := c.post(ctx, "/v1/check", lockfileJSON, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RecentIntel fetches recent threat-intel events from the platform. The
// /v1/intel/recent feed is public, so no API key is required.
func (c *Client) RecentIntel(ctx context.Context, limit int) ([]IntelEvent, error) {
	path := fmt.Sprintf("/v1/intel/recent?limit=%d", limit)
	var events []IntelEvent
	if err := c.get(ctx, path, &events); err != nil {
		return nil, err
	}
	return events, nil
}

// get performs an authenticated GET request and decodes the JSON response.
func (c *Client) get(ctx context.Context, path string, dst any) error {
	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("platform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("platform: invalid API key")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("platform: rate limit exceeded")
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("platform: not found")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("platform returned %d", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(lr).Decode(dst); err != nil {
		return fmt.Errorf("decode platform response: %w", err)
	}
	return nil
}

// post performs an authenticated POST request with JSON body.
func (c *Client) post(ctx context.Context, path string, body []byte, dst any) error {
	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("platform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("platform returned %d", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(lr).Decode(dst); err != nil {
		return fmt.Errorf("decode platform response: %w", err)
	}
	return nil
}

// Cache helpers.

func (c *Client) getCache(key string) any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.data
}

func (c *Client) setCache(key string, data any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = &cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(cacheTTL),
	}
}
