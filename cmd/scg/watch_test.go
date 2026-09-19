package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/platform"
)

// watch uploads the signed lockfile with the repository, refuses an
// unsigned one, and turns a plan refusal into an operational exit.
func TestWatchUploadsTheLockfile(t *testing.T) {
	for _, k := range []string{"SCG_REPO", "GITHUB_REPOSITORY", "CI_PROJECT_URL"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "scg.lock")
	signer := testSigner(t)
	lf := lockfileWith(manifest.ToolEntry{Ecosystem: "github_action", Reference: "actions/checkout@v4", Hash: "abc", Algorithm: "sha1"})
	if err := signer.SignLockfile(context.Background(), lf); err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}

	var gotRepo string
	var gotBody manifest.Lockfile
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/lockfile" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer scg_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		gotRepo = r.URL.Query().Get("repo")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		if status == http.StatusPaymentRequired {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"your plan watches one repository","feature":"multi_repo","required_plan":"pro"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"repo":"` + gotRepo + `","tools_watched":1,"added":1,"removed":0,"repos_watched":1}`))
	}))
	defer srv.Close()
	client := platform.NewClient(srv.URL, "scg_test")

	res, err := doWatch(context.Background(), client, path, "github.com/acme/app")
	if err != nil || res.ToolsWatched != 1 || gotRepo != "github.com/acme/app" || len(gotBody.Pipelines) != 1 {
		t.Fatalf("watch = %+v, %v (repo %q)", res, err, gotRepo)
	}
	// A plan refusal is operational, not a finding.
	status = http.StatusPaymentRequired
	_, err = doWatch(context.Background(), client, path, "github.com/acme/other")
	if !errors.Is(err, platform.ErrNotEntitled) || !strings.Contains(err.Error(), "one repository") {
		t.Fatalf("402: %v", err)
	}
	if exitCodeFor(classifyEntitlement(err)) != ExitOperational {
		t.Fatalf("402 must exit 2, got %d", exitCodeFor(classifyEntitlement(err)))
	}
	// No key: operational.
	if _, err := doWatch(context.Background(), platform.NewClient(srv.URL, ""), path, "github.com/acme/app"); exitCodeFor(err) != ExitOperational {
		t.Fatalf("no key: %v", err)
	}
	// Unsigned lockfile: refused.
	unsigned := filepath.Join(dir, "unsigned.lock")
	if err := manifest.WriteLockfile(unsigned, lockfileWith(manifest.ToolEntry{Ecosystem: "npm", Reference: "x@1", Hash: "h", Algorithm: "sha256"})); err != nil {
		t.Fatal(err)
	}
	if _, err := doWatch(context.Background(), client, unsigned, "github.com/acme/app"); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned: %v", err)
	}
	// No repository to be found: says how to pass one.
	if _, err := doWatch(context.Background(), client, path, ""); err == nil || !strings.Contains(err.Error(), "--repo") {
		t.Fatalf("undetectable repo: %v", err)
	}
}

// fakePlatform serves the watch and intel routes the commands use.
func fakePlatform(t *testing.T, key string) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodDelete:
			if r.URL.Query().Get("repo") == "github.com/acme/gone" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/lockfile":
			_, _ = w.Write([]byte(`{"ok":true,"repo":"github.com/acme/app","tools_watched":1,"added":1,"removed":0,"repos_watched":1}`))
		case r.URL.Path == "/v1/watches" && r.URL.Query().Get("repo") != "":
			_, _ = w.Write([]byte(`{"organization":"acme","repos":[{"repo":"github.com/acme/app","tools":1,"updated_at":"2026-09-20T00:00:00Z"}],"watches":[{"repo":"github.com/acme/app","ecosystem":"github_action","reference":"actions/checkout@v4","source":"lockfile","created_at":"2026-09-20T00:00:00Z"}],"total":1,"repo_limit":1}`))
		case r.URL.Path == "/v1/watches":
			_, _ = w.Write([]byte(`{"organization":"acme","repos":[{"repo":"github.com/acme/app","tools":1,"updated_at":"2026-09-20T00:00:00Z"},{"repo":"","tools":2,"updated_at":"2026-09-20T00:00:00Z"}],"total":3,"repo_limit":1}`))
		case r.URL.Path == "/v1/intel/private/stix":
			_, _ = w.Write([]byte(`{"type":"bundle","objects":[]}`))
		case r.URL.Path == "/v1/intel/private":
			_, _ = w.Write([]byte(`[{"id":"p1","type":"watched_drift","severity":"critical","ecosystem":"github_action","tool":"actions/checkout@v4","repos":["github.com/acme/app","github.com/acme/web"],"summary":"tag moved","ts":"2026-09-20T00:00:00Z"}]`))
		default:
			_, _ = w.Write([]byte(`[{"id":"e1","type":"drift","severity":"critical","ecosystem":"github_action","tool":"actions/checkout@v4","summary":"tag moved"}]`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func signedLockfile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "scg.lock")
	lf := lockfileWith(manifest.ToolEntry{Ecosystem: "github_action", Reference: "actions/checkout@v4", Hash: "abc", Algorithm: "sha1"})
	if err := testSigner(t).SignLockfile(context.Background(), lf); err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}
	return path
}

// The watch commands run end to end against a fake platform, keyed from
// the environment as in CI, and without a key they exit 2.
func TestWatchCommands(t *testing.T) {
	srv, paths := fakePlatform(t, "scg_ci")
	t.Setenv("SCG_PLATFORM_URL", srv.URL)
	t.Setenv("SCG_API_KEY", "scg_ci")
	t.Setenv("SCG_CONFIG_DIR", t.TempDir())
	t.Setenv("SCG_REPO", "github.com/acme/app")
	path := signedLockfile(t, t.TempDir())
	ctx := context.Background()

	if err := runWatch(ctx, []string{"--lockfile", path}); err != nil {
		t.Fatalf("watch: %v", err)
	}
	if err := runWatch(ctx, []string{"--lockfile", path, "--json"}); err != nil {
		t.Fatalf("watch --json: %v", err)
	}
	if err := watchAfterWrite(ctx, path, ""); err != nil {
		t.Fatalf("init --watch: %v", err)
	}
	for _, args := range [][]string{nil, {"--json"}, {"--repo", "github.com/acme/app"}} {
		if err := runWatches(ctx, args); err != nil {
			t.Fatalf("watches %v: %v", args, err)
		}
	}
	if err := runUnwatch(ctx, nil); err != nil {
		t.Fatalf("unwatch: %v", err)
	}
	if err := runUnwatch(ctx, []string{"--repo", "github.com/acme/gone"}); err == nil || !strings.Contains(err.Error(), "not watched") {
		t.Fatalf("unwatch unknown: %v", err)
	}
	if err := runUnwatch(ctx, []string{"--all"}); err != nil {
		t.Fatalf("unwatch --all: %v", err)
	}
	for _, args := range [][]string{{"--watched"}, {"--private"}, {"--private", "--json"}, {"--private", "--stix"}, {"--watched", "--json"}} {
		if err := runIntel(ctx, args); err != nil {
			t.Fatalf("intel %v: %v", args, err)
		}
	}
	if len(*paths) == 0 || !strings.Contains(strings.Join(*paths, "|"), "GET /v1/intel/private/stix") {
		t.Fatalf("paths = %v", *paths)
	}
	if joinRepos([]string{"a", "b"}) != "a, b" {
		t.Fatal("joinRepos")
	}

	// A wrong key is operational, never a finding.
	t.Setenv("SCG_API_KEY", "scg_wrong")
	if err := runWatches(ctx, nil); exitCodeFor(err) != ExitOperational {
		t.Fatalf("wrong key: %v", err)
	}
	t.Setenv("SCG_API_KEY", "")
	for name, run := range map[string]func(context.Context, []string) error{"watch": runWatch, "unwatch": runUnwatch, "watches": runWatches} {
		if err := run(ctx, []string{"--lockfile", path}[:map[bool]int{true: 2, false: 0}[name == "watch"]]); exitCodeFor(err) != ExitOperational {
			t.Fatalf("%s without key: %v", name, err)
		}
	}
}
