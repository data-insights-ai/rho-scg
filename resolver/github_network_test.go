package resolver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testGitHubResolver creates a GitHubResolver pointed at a test server.
func testGitHubResolver(server *httptest.Server) *GitHubResolver {
	r := NewGitHubResolver("test-token")
	r.client = server.Client()
	// Override the base URL by replacing the client transport.
	r.client.Transport = &rewriteTransport{
		base:    server.Client().Transport,
		baseURL: server.URL,
	}
	return r
}

// rewriteTransport rewrites all requests to point at the test server.
type rewriteTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.baseURL[len("http://"):]
	return t.base.RoundTrip(req)
}

func TestGitHubResolver_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // hang
	}))
	defer server.Close()

	r := testGitHubResolver(server)
	r.client.Timeout = 100 * time.Millisecond

	ctx := context.Background()
	_, err := r.Resolve(ctx, "actions/checkout@v4")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestGitHubResolver_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	r := testGitHubResolver(server)
	ctx := context.Background()
	_, err := r.Resolve(ctx, "nonexistent/repo@v1")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestGitHubResolver_500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	r := testGitHubResolver(server)
	ctx := context.Background()
	_, err := r.Resolve(ctx, "actions/checkout@v4")
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestGitHubResolver_RateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	r := testGitHubResolver(server)
	ctx := context.Background()
	_, err := r.Resolve(ctx, "actions/checkout@v4")
	if err == nil {
		t.Fatal("expected error for rate limit")
	}
}

func TestGitHubResolver_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	r := testGitHubResolver(server)
	ctx := context.Background()
	_, err := r.Resolve(ctx, "actions/checkout@v4")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestGitHubResolver_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"object":{"sha":"","type":"commit"}}`))
	}))
	defer server.Close()

	r := testGitHubResolver(server)
	ctx := context.Background()
	_, err := r.Resolve(ctx, "actions/checkout@v4")
	if err == nil {
		t.Fatal("expected error for empty SHA response")
	}
}

func TestGitHubResolver_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	r := testGitHubResolver(server)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := r.Resolve(ctx, "actions/checkout@v4")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestParseActionRef_Adversarial(t *testing.T) {
	adversarial := []string{
		"",
		"@",
		"@v1",
		"owner/@v1",
		"/repo@v1",
		"owner/repo@",
		string(make([]byte, 10000)) + "@v1", // 10KB owner
		"owner/repo@" + string(make([]byte, 10000)), // 10KB ref
		"owner\x00/repo@v1",                         // null byte
		"owner/repo\n@v1",                           // newline
		"owner/repo@v1\r\nHost: evil.com",           // header injection attempt
	}

	for _, input := range adversarial {
		_, _, _, err := parseActionRef(input)
		// We don't require all to error, but none should panic.
		_ = err
	}
}
