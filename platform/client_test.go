package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := NewClient(srv.URL, "")
	c.RetryBackoff = time.Millisecond // keep tests fast
	return c
}

func TestClient_Resolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "scg/") {
			t.Errorf("User-Agent = %q, want a scg/<version> identifier", got)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"hash":"abc","algorithm":"sha1","source":"api.github.com","stale":false}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	res, err := newTestClient(t, srv).Resolve(context.Background(), "github_action", "actions/checkout@v4")
	if err != nil {
		t.Fatal(err)
	}
	if res.Hash != "abc" {
		t.Errorf("Hash = %q, want abc", res.Hash)
	}
}

// Callers need to branch on WHY a request failed — a rate limit is retryable
// and a bad key is not. Matching on error strings, which is all the old client
// allowed, makes that impossible to do safely.
func TestClient_SentinelErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{"unauthorized", http.StatusUnauthorized, ErrUnauthorized},
		{"rate limited", http.StatusTooManyRequests, ErrRateLimited},
		{"not found", http.StatusNotFound, ErrNotFound},
		{"server error", http.StatusInternalServerError, ErrUnavailable},
		{"bad gateway", http.StatusBadGateway, ErrUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			_, err := newTestClient(t, srv).Resolve(context.Background(), "github_action", "x@v1")
			if !errors.Is(err, tt.want) {
				t.Errorf("got %v, want errors.Is(..., %v)", err, tt.want)
			}
		})
	}
}

// A transient 503 must not fail a CI gate. The old client had no retry at all,
// so one blip failed the build in a way indistinguishable from a real finding.
func TestClient_RetriesTransientFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"hash":"recovered","algorithm":"sha1"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	res, err := newTestClient(t, srv).Resolve(context.Background(), "github_action", "x@v1")
	if err != nil {
		t.Fatalf("client must retry a transient failure: %v", err)
	}
	if res.Hash != "recovered" {
		t.Errorf("Hash = %q, want recovered", res.Hash)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("made %d attempts, want 3", got)
	}
}

// A 401 is not going to become a 200. Retrying it wastes the user's time and,
// on a rate-limited endpoint, their remaining quota.
func TestClient_DoesNotRetryPermanentFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, _ = newTestClient(t, srv).Resolve(context.Background(), "github_action", "x@v1")
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d attempts, want 1 — a 401 must not be retried", got)
	}
}

// The server's own backoff hint must win over the client's guess.
func TestClient_HonoursRetryAfter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"hash":"ok"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	c.MaxRetries = 2
	if _, err := c.Resolve(context.Background(), "github_action", "x@v1"); err != nil {
		t.Fatalf("a Retry-After: 0 rate limit should be retried immediately: %v", err)
	}
}

// The cache must actually prevent a second request; that is its entire job on a
// 20-requests-per-hour budget.
func TestClient_CachesResolutions(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"hash":"abc"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	for i := 0; i < 5; i++ {
		if _, err := c.Resolve(context.Background(), "github_action", "actions/checkout@v4"); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d requests for the same reference, want 1", got)
	}
}

// A non-HTTPS platform URL would send the API key in clear text.
func TestNewClient_RejectsPlaintextURL(t *testing.T) {
	c := NewClient("http://api.example.com", "secret-key")
	_, err := c.Resolve(context.Background(), "github_action", "x@v1")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("an API key must not be sent over plaintext http, got: %v", err)
	}
}

// Localhost over http is how people run the platform locally; refusing it would
// make development impossible for no security gain.
func TestNewClient_AllowsLocalhostPlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"hash":"abc"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "secret-key")
	c.RetryBackoff = time.Millisecond
	if _, err := c.Resolve(context.Background(), "github_action", "x@v1"); err != nil {
		t.Errorf("a loopback platform URL must be usable: %v", err)
	}
}

func TestClient_RespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := newTestClient(t, srv)
	if _, err := c.Resolve(ctx, "github_action", "x@v1"); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
}

func TestClient_FetchProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"tool":"actions/checkout","risk_tier":2,
			"required_secrets":["GITHUB_TOKEN"],
			"forbidden_patterns":[{"pattern":"^AWS_","reason":"no cloud creds in checkout"}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	p, err := newTestClient(t, srv).FetchProfile(context.Background(), "github_action", "actions/checkout")
	if err != nil {
		t.Fatal(err)
	}
	if p.RiskTier != 2 || len(p.ForbiddenSecrets) != 1 {
		t.Errorf("unexpected profile: %+v", p)
	}
	if p.ForbiddenSecrets[0].Pattern != "^AWS_" {
		t.Errorf("Pattern = %q", p.ForbiddenSecrets[0].Pattern)
	}
}

func TestClient_Sign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"algorithm":"ed25519-platform","key_id":"abc","value":"sig","public_key":"pk"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	got, err := newTestClient(t, srv).Sign(context.Background(), []byte(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Algorithm != "ed25519-platform" || got.KeyID != "abc" {
		t.Errorf("unexpected sign response: %+v", got)
	}
}

// Check is the one endpoint that genuinely needs an account; without a key it
// must say so rather than issue a request that will be rejected.
func TestClient_CheckRequiresAPIKey(t *testing.T) {
	c := NewClient("https://api.example.com", "")
	if _, err := c.Check(context.Background(), []byte("{}")); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("got %v, want ErrNotConfigured", err)
	}
}

func TestClient_RecentIntel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`[{"id":"e1","type":"drift","severity":"critical",
			"ecosystem":"github_action","tool":"actions/checkout@v4","summary":"tag moved"}]`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	events, err := newTestClient(t, srv).RecentIntel(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "drift" {
		t.Errorf("unexpected events: %+v", events)
	}
}

func TestClient_IsConfiguredAndBaseURL(t *testing.T) {
	c := NewClient("https://api.example.com/", "key")
	if !c.IsConfigured() {
		t.Error("a client with a key is configured")
	}
	// A trailing slash on the base URL would produce //v1/resolve paths.
	if c.BaseURL() != "https://api.example.com" {
		t.Errorf("BaseURL = %q, want the trailing slash trimmed", c.BaseURL())
	}
	if NewClient("https://api.example.com", "").IsConfigured() {
		t.Error("a client with no key is not configured")
	}
}

// The cache must not hand a *ProfileResponse back to a caller asking for a
// *ResolveResponse. The previous unchecked type assertion would have panicked.
func TestClient_CacheIsTypeSafe(t *testing.T) {
	c := NewClient("https://api.example.com", "")
	c.setCache("resolve:github_action:x@v1", &ProfileResponse{Tool: "x"})

	if _, ok := getCache[*ResolveResponse](c, "resolve:github_action:x@v1"); ok {
		t.Error("a cache entry of the wrong type must be treated as a miss, not returned")
	}
}

func TestClient_CacheExpires(t *testing.T) {
	c := NewClient("https://api.example.com", "")
	c.setCache("k", &ResolveResponse{Hash: "abc"})

	c.mu.Lock()
	c.cache["k"].expiresAt = time.Now().Add(-time.Minute)
	c.mu.Unlock()

	if _, ok := getCache[*ResolveResponse](c, "k"); ok {
		t.Error("an expired cache entry must be a miss")
	}
}
