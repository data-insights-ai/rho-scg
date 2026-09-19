package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/data-insights-ai/rho-scg/resolver"
)

func resolverAgainst(t *testing.T, body string) *PlatformResolver {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "")
	c.RetryBackoff = time.Millisecond
	return NewPlatformResolver(c, resolver.EcoGitHubAction)
}

func TestPlatformResolver_Resolve(t *testing.T) {
	r := resolverAgainst(t, `{"hash":"abc123","algorithm":"sha1","source":"api.github.com",
	                          "resolved_at":"2026-09-08T10:00:00Z","stale":false,"age_seconds":60}`)

	res, err := r.Resolve(context.Background(), "actions/checkout@v4")
	if err != nil {
		t.Fatal(err)
	}
	if res.Hash != "abc123" {
		t.Errorf("Hash = %q, want abc123", res.Hash)
	}
	if res.Source != "platform:api.github.com" {
		t.Errorf("Source = %q, want the platform-prefixed origin", res.Source)
	}
	if r.Ecosystem() != resolver.EcoGitHubAction {
		t.Errorf("Ecosystem = %q", r.Ecosystem())
	}
}

// ResolvedAt must be the platform's own last confirmation, not the moment we
// asked. Stamping time.Now() here made every answer look fresh no matter how
// old the underlying data was — which is precisely how stale digests passed as
// verified.
func TestPlatformResolver_ResolvedAtIsThePlatformsConfirmation(t *testing.T) {
	r := resolverAgainst(t, `{"hash":"abc","resolved_at":"2026-03-01T00:00:00Z","age_seconds":100}`)

	res, err := r.Resolve(context.Background(), "actions/checkout@v4")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if !res.ResolvedAt.Equal(want) {
		t.Errorf("ResolvedAt = %v, want the platform's confirmation time %v", res.ResolvedAt, want)
	}
}

// A platform that reports stale data must be reportable as stale by the
// resolver, or the caller has no way to refuse to trust it.
func TestPlatformResolver_ReportsFreshness(t *testing.T) {
	r := resolverAgainst(t, `{"hash":"abc","stale":true,"age_seconds":86400}`)

	if _, err := r.Resolve(context.Background(), "actions/checkout@v4"); err != nil {
		t.Fatal(err)
	}

	stale, age := r.Freshness("actions/checkout@v4")
	if !stale {
		t.Error("the resolver must report the platform's stale flag")
	}
	if age != 24*time.Hour {
		t.Errorf("age = %v, want 24h", age)
	}

	// It must satisfy the interface the check path uses to ask.
	var _ resolver.FreshnessReporter = r
}

// A reference never resolved has no freshness opinion, and must not read as
// stale by default — that would fail every check for the wrong reason.
func TestPlatformResolver_UnknownReferenceIsNotStale(t *testing.T) {
	r := resolverAgainst(t, `{"hash":"abc"}`)
	stale, age := r.Freshness("never/asked@v1")
	if stale || age != 0 {
		t.Errorf("Freshness for an unresolved reference = (%v, %v), want (false, 0)", stale, age)
	}
}

func TestPlatformResolver_PropagatesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	c.RetryBackoff = time.Millisecond
	r := NewPlatformResolver(c, resolver.EcoNPM)

	if _, err := r.Resolve(context.Background(), "left-pad@1.0.0"); err == nil {
		t.Fatal("a missing reference must surface as an error")
	}
}
