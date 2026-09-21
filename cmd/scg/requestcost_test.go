package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// countingPlatform stands in for the platform and records what each command
// asks it for. The plans sell API requests, so the number a command spends
// is a product fact and has to be measured rather than estimated.
type countingPlatform struct {
	mu     sync.Mutex
	byPath map[string]int
	total  int
}

func (c *countingPlatform) record(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case strings.HasPrefix(path, "/v1/resolve/batch"):
		c.byPath["resolve/batch"]++
	case strings.HasPrefix(path, "/v1/resolve/"):
		c.byPath["resolve"]++
	case strings.HasPrefix(path, "/v1/sign"):
		c.byPath["sign"]++
	case strings.HasPrefix(path, "/v1/profile/"):
		c.byPath["profile"]++
	default:
		c.byPath[path]++
	}
	c.total++
}

func (c *countingPlatform) counts() (map[string]int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]int{}
	for k, v := range c.byPath {
		out[k] = v
	}
	return out, c.total
}

// newCountingPlatform answers resolve, batch resolve and sign well enough
// for a whole init/check cycle, and counts every request.
func newCountingPlatform(t *testing.T, hashes map[string]string) *countingPlatform {
	t.Helper()
	c := &countingPlatform{byPath: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.record(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/resolve/batch":
			var req struct {
				Refs []struct{ Ecosystem, Reference string } `json:"refs"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			items := make([]map[string]any, 0, len(req.Refs))
			for _, ref := range req.Refs {
				items = append(items, resolveBody(ref.Ecosystem, ref.Reference, hashes))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": items})
		case strings.HasPrefix(r.URL.Path, "/v1/resolve/"):
			rest := strings.TrimPrefix(r.URL.Path, "/v1/resolve/")
			eco, ref, _ := strings.Cut(rest, "/")
			_ = json.NewEncoder(w).Encode(resolveBody(eco, ref, hashes))
		case strings.HasPrefix(r.URL.Path, "/v1/sign"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"signature": "AA==", "key_id": "test", "algorithm": "ed25519-platform",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SCG_PLATFORM_URL", srv.URL)
	return c
}

func resolveBody(eco, ref string, hashes map[string]string) map[string]any {
	hash := hashes[ref]
	if hash == "" {
		hash = "0000000000000000000000000000000000000000"
	}
	return map[string]any{
		"ecosystem": eco, "reference": ref, "hash": hash,
		"algorithm": "sha256", "source": "test", "stale": false,
		"resolved_at": "2026-09-21T06:00:00Z", "freshness_budget_seconds": 21600,
	}
}

// What a run costs against the hourly allowance, measured rather than
// estimated: init resolves each distinct reference and signs once, and a
// check spends one batch request for a whole ecosystem.
func TestRequestCost_InitAndCheck(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"),
		[]byte("httpx==0.28.1\nboto3==1.34.0\nclick==8.1.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	counter := newCountingPlatform(t, nil)

	lockfilePath := filepath.Join(root, "scg.lock")
	workflows := filepath.Join(root, ".github", "workflows")
	if err := doInit(context.Background(), quietLogger(), root, workflows, lockfilePath,
		buildResolvers(), testSigner(t)); err != nil {
		t.Fatal(err)
	}
	initCounts, initTotal := counter.counts()
	if initCounts["resolve/batch"] != 1 || initCounts["resolve"] != 0 {
		t.Errorf("init spent %v (%d requests); expected one batch for the ecosystem and no single lookups",
			initCounts, initTotal)
	}

	before := initTotal
	if _, err := doCheckDetailed(context.Background(), quietLogger(), root, workflows, lockfilePath, ""); err != nil {
		t.Fatalf("check: %v", err)
	}
	checkCounts, checkTotal := counter.counts()
	batches := checkCounts["resolve/batch"] - initCounts["resolve/batch"]
	singles := checkCounts["resolve"] - initCounts["resolve"]
	if batches != 1 {
		t.Errorf("check spent %d batch requests, expected one for the ecosystem", batches)
	}
	if singles != 0 {
		t.Errorf("check resolved %d references one by one after the batch; the batch should answer them", singles)
	}
	t.Logf("measured cost: init %d requests (%v), check %d requests (%v)",
		before, initCounts, checkTotal-before, map[string]int{"resolve/batch": batches, "resolve": singles})
}

// Signing is one request whatever the project's size, so a large baseline
// does not multiply the fixed cost.
func TestRequestCost_SignsOnce(t *testing.T) {
	root := t.TempDir()
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, fmt.Sprintf("pkg%d==1.0.%d", i, i))
	}
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	counter := newCountingPlatform(t, nil)
	// The platform signer is used here on purpose: signing is a request and
	// belongs in the measurement.
	if err := doInit(context.Background(), quietLogger(), root, filepath.Join(root, ".github", "workflows"),
		filepath.Join(root, "scg.lock"), buildResolvers(), newPlatformSigner()); err != nil {
		t.Fatal(err)
	}
	counts, total := counter.counts()
	if counts["sign"] != 1 {
		t.Errorf("signing cost %d requests for 40 dependencies, expected one", counts["sign"])
	}
	// One batch for the ecosystem, not one request per dependency: the
	// difference is 41 requests against an hourly allowance versus two.
	if counts["resolve/batch"] != 1 || counts["resolve"] != 0 {
		t.Errorf("resolution cost %v for 40 dependencies, expected a single batch", counts)
	}
	if total > 3 {
		t.Errorf("a 40-dependency project cost %d requests: %v", total, counts)
	}
	t.Logf("40 dependencies cost %d requests: %v", total, counts)
}
