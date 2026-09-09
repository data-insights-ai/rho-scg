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
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sentinel errors. Callers must be able to branch on why a call failed: a rate
// limit is worth retrying and reporting as an operational problem, a bad key
// needs the user to act, and a missing tool is a finding. The previous client
// returned bare fmt.Errorf strings, so the only way to tell these apart was
// substring matching on an error message.
var (
	// ErrNotConfigured indicates no platform API key is set.
	ErrNotConfigured = errors.New("SCG platform not configured: set SCG_API_KEY for access to pre-computed hashes and curated profiles")
	// ErrUnauthorized means the API key was rejected.
	ErrUnauthorized = errors.New("platform rejected the API key")
	// ErrRateLimited means the caller is over its request budget.
	ErrRateLimited = errors.New("platform rate limit exceeded")
	// ErrNotFound means the platform has no record of the reference.
	ErrNotFound = errors.New("not found in the platform database")
	// ErrUnavailable means the platform could not answer — a network failure or
	// a 5xx. Distinct from every other error because it says nothing about the
	// supply chain, only about the service.
	ErrUnavailable = errors.New("platform unavailable")
)

const (
	maxResponseBytes = 10 * 1024 * 1024 // 10MB
	cacheTTL         = 5 * time.Minute

	defaultMaxRetries   = 3
	defaultRetryBackoff = 500 * time.Millisecond
	defaultTimeout      = 30 * time.Second
)

// Version is stamped into the User-Agent so the platform can attribute traffic
// and correlate a client bug with a release. Overridden from main at build time.
var Version = "dev"

// Client is the SCG Platform API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client

	// MaxRetries bounds retry attempts for transient failures.
	MaxRetries int
	// RetryBackoff is the base delay between attempts; it doubles each time.
	RetryBackoff time.Duration

	// In-memory cache (5 min TTL).
	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	data      any
	expiresAt time.Time
}

// NewClient creates a new Platform API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		apiKey:       apiKey,
		httpClient:   &http.Client{Timeout: defaultTimeout},
		MaxRetries:   defaultMaxRetries,
		RetryBackoff: defaultRetryBackoff,
		cache:        make(map[string]*cacheEntry),
	}
}

// IsConfigured reports whether the platform API key is set.
func (c *Client) IsConfigured() bool { return c.apiKey != "" }

// BaseURL returns the configured platform endpoint.
func (c *Client) BaseURL() string { return c.baseURL }

// checkTransport refuses to send an API key over an unencrypted connection.
// Loopback is exempt so the platform can be run locally during development.
func (c *Client) checkTransport() error {
	if c.apiKey == "" {
		return nil
	}
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("invalid platform URL %q: %w", c.baseURL, err)
	}
	if u.Scheme == "https" || isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("refusing to send the API key to %q over %s: use https", c.baseURL, u.Scheme)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Resolve fetches a pre-computed resolution from the platform.
func (c *Client) Resolve(ctx context.Context, ecosystem, reference string) (*ResolveResponse, error) {
	cacheKey := "resolve:" + ecosystem + ":" + reference
	if cached, ok := getCache[*ResolveResponse](c, cacheKey); ok {
		return cached, nil
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
	if cached, ok := getCache[*ProfileResponse](c, cacheKey); ok {
		return cached, nil
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
	return c.do(ctx, http.MethodGet, path, nil, dst)
}

// post performs an authenticated POST request with a JSON body.
func (c *Client) post(ctx context.Context, path string, body []byte, dst any) error {
	return c.do(ctx, http.MethodPost, path, body, dst)
}

// do issues a request, retrying transient failures with exponential backoff.
//
// Only transient conditions are retried: network errors, 5xx, and 429. A 401 or
// a 404 will not change on the next attempt, and retrying a 429 without
// honouring the server's Retry-After just spends the remaining budget faster.
func (c *Client) do(ctx context.Context, method, path string, body []byte, dst any) error {
	if err := c.checkTransport(); err != nil {
		return err
	}

	attempts := c.MaxRetries
	if attempts < 1 {
		attempts = 1
	}
	backoff := c.RetryBackoff
	if backoff <= 0 {
		backoff = defaultRetryBackoff
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			wait := backoff << (attempt - 1)
			if hinted := retryAfterHint(lastErr); hinted >= 0 {
				wait = hinted
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		err := c.attempt(ctx, method, path, body, dst)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable(err) {
			return err
		}
	}
	return lastErr
}

// attempt performs exactly one request.
func (c *Client) attempt(ctx context.Context, method, path string, body []byte, dst any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "scg/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() {
		// Drain before closing so the connection can be reused; a body left
		// unread forces a new TCP handshake for every request.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if err := statusError(resp); err != nil {
		return err
	}

	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(lr).Decode(dst); err != nil {
		return fmt.Errorf("decode platform response: %w", err)
	}
	return nil
}

// statusError maps an HTTP status onto a sentinel error.
func statusError(resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return ErrUnauthorized
	case resp.StatusCode == http.StatusTooManyRequests:
		return &rateLimitError{retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: platform returned %d", ErrUnavailable, resp.StatusCode)
	default:
		return fmt.Errorf("platform returned %d", resp.StatusCode)
	}
}

// rateLimitError carries the server's backoff hint alongside ErrRateLimited.
type rateLimitError struct{ retryAfter time.Duration }

func (e *rateLimitError) Error() string {
	if e.retryAfter > 0 {
		return fmt.Sprintf("%s, retry after %s", ErrRateLimited, e.retryAfter)
	}
	return ErrRateLimited.Error()
}
func (e *rateLimitError) Unwrap() error { return ErrRateLimited }

// parseRetryAfter reads a Retry-After header expressed in seconds. A present
// but zero value is meaningful ("retry now") and must be distinguishable from
// an absent header, so callers use retryAfterHint's -1 sentinel.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return -1
	}
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs < 0 {
		return -1
	}
	return time.Duration(secs) * time.Second
}

// retryAfterHint returns the server's requested delay, or -1 if it gave none.
func retryAfterHint(err error) time.Duration {
	var rle *rateLimitError
	if errors.As(err, &rle) {
		return rle.retryAfter
	}
	return -1
}

// retryable reports whether another attempt could plausibly succeed.
func retryable(err error) bool {
	return errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRateLimited)
}

// Cache helpers.

// getCache reads a typed value from the cache. The type parameter replaces an
// unchecked type assertion that would have panicked on a key collision.
func getCache[T any](c *Client, key string) (T, bool) {
	var zero T
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return zero, false
	}
	v, ok := entry.data.(T)
	if !ok {
		return zero, false
	}
	return v, true
}

func (c *Client) setCache(key string, data any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Evict expired entries opportunistically. The map previously grew without
	// bound; harmless for a one-shot CLI run, not for a long-lived process.
	now := time.Now()
	if len(c.cache) > 512 {
		for k, e := range c.cache {
			if now.After(e.expiresAt) {
				delete(c.cache, k)
			}
		}
	}
	c.cache[key] = &cacheEntry{data: data, expiresAt: now.Add(cacheTTL)}
}
