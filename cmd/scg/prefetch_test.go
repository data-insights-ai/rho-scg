package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/platform"
	"github.com/data-insights-ai/rho-scg/resolver"
)

// A check with several tools costs one request: the batch endpoint answers
// them all and the per-reference lookups come from the cache. A platform
// without the endpoint is asked one by one.
func TestDetectDrift_OneRequestPerLockfile(t *testing.T) {
	var batch, single atomic.Int32
	hasBatch := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/resolve/batch" && hasBatch:
			batch.Add(1)
			var req struct {
				Refs []platform.BatchRef `json:"refs"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			var items []map[string]any
			for _, ref := range req.Refs {
				items = append(items, map[string]any{"ecosystem": ref.Ecosystem, "reference": ref.Reference, "hash": "h-" + ref.Reference, "algorithm": "sha1", "resolved_at": "2026-09-20T00:00:00Z", "stale": false, "age_seconds": 5})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": items})
		case r.URL.Path == "/v1/resolve/batch":
			http.NotFound(w, r)
		default:
			single.Add(1)
			ref := r.URL.Path[len("/v1/resolve/github_action/"):]
			_ = json.NewEncoder(w).Encode(map[string]any{"hash": "h-" + ref, "algorithm": "sha1", "resolved_at": "2026-09-20T00:00:00Z", "stale": false, "age_seconds": 5})
		}
	}))
	defer srv.Close()
	lf := lockfileWith(
		manifest.ToolEntry{Ecosystem: "github_action", Reference: "a/one@v1", Hash: "h-a/one@v1", Algorithm: "sha1"},
		manifest.ToolEntry{Ecosystem: "github_action", Reference: "a/two@v1", Hash: "h-a/two@v1", Algorithm: "sha1"},
		manifest.ToolEntry{Ecosystem: "github_action", Reference: "a/three@v1", Hash: "old", Algorithm: "sha1"},
	)
	run := func() ([]manifest.DriftResult, []string) {
		client := platform.NewClient(srv.URL, "")
		resolvers := map[resolver.Ecosystem]resolver.Resolver{
			resolver.EcoGitHubAction: platform.NewPlatformResolver(client, resolver.EcoGitHubAction),
		}
		drift, warnings, err := detectDriftWithPartialFailure(context.Background(), lf, resolvers, quietLogger())
		if err != nil {
			t.Fatal(err)
		}
		return drift, warnings
	}
	drift, warnings := run()
	if batch.Load() != 1 || single.Load() != 0 {
		t.Fatalf("batch %d single %d; want one batch request and nothing else", batch.Load(), single.Load())
	}
	if len(drift) != 1 || drift[0].Reference != "a/three@v1" || len(warnings) != 0 {
		t.Fatalf("drift = %v warnings = %v", drift, warnings)
	}
	hasBatch = false
	drift, _ = run()
	if single.Load() != 3 || len(drift) != 1 {
		t.Fatalf("fallback: %d single requests, drift %v", single.Load(), drift)
	}
}

// In --json mode a command writes its result and hands main the exit code
// instead of exiting itself, so the path is testable: drift is exit 1,
// a plan refusal exit 2, and the schema is versioned.
func TestRunCheck_JSONReportsAndReturnsTheExitCode(t *testing.T) {
	for _, k := range []string{"SCG_REPO", "GITHUB_REPOSITORY", "CI_PROJECT_URL"} {
		t.Setenv(k, "")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/resolve/batch" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"hash": "moved", "algorithm": "sha1", "resolved_at": "2026-09-20T00:00:00Z", "stale": false, "age_seconds": 5})
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)
	t.Setenv("SCG_API_KEY", "")
	t.Setenv("SCG_CONFIG_DIR", t.TempDir())
	path := signedLockfile(t, t.TempDir())

	out := captureStdout(t, func() {
		err := runCheck(context.Background(), []string{"--lockfile", path, "--json"})
		var reported *reportedError
		if !errors.As(err, &reported) || reported.code != ExitFinding || exitCodeFor(err) != ExitFinding {
			t.Fatalf("check --json with drift: %v", err)
		}
	})
	var res JSONResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %s", out)
	}
	if res.SchemaVersion != jsonSchemaVersion || res.Status != "drift_detected" || res.ExitCode != ExitFinding || len(res.Drift) != 1 || res.Summary == nil || res.Summary.Drifted != 1 {
		t.Fatalf("result = %+v", res)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}
