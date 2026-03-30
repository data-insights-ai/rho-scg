package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/parser"
	"github.com/data-insights-ai/rho-scg/resolver"
)

// mockResolver returns canned resolutions for testing without network calls.
type mockResolver struct {
	resolutions map[string]*resolver.Resolution
}

func newMockResolver() *mockResolver {
	now := time.Date(2026, 3, 28, 10, 0, 0, 0, time.UTC)
	return &mockResolver{
		resolutions: map[string]*resolver.Resolution{
			"actions/checkout@v4": {
				Original:   "actions/checkout@v4",
				Hash:       "b4ffde65f46336ab88eb53be808477a3936bae11",
				Algorithm:  "sha256",
				Canonical:  "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
				Source:     "mock",
				ResolvedAt: now,
			},
			"actions/setup-go@v5": {
				Original:   "actions/setup-go@v5",
				Hash:       "0aaccfd150a27a34a12cf405e5a1e58deff3170e",
				Algorithm:  "sha256",
				Canonical:  "actions/setup-go@0aaccfd150a27a34a12cf405e5a1e58deff3170e",
				Source:     "mock",
				ResolvedAt: now,
			},
			"aquasecurity/trivy-action@v1": {
				Original:   "aquasecurity/trivy-action@v1",
				Hash:       "57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
				Algorithm:  "sha256",
				Canonical:  "aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
				Source:     "mock",
				ResolvedAt: now,
			},
			"docker/build-push-action@v5": {
				Original:   "docker/build-push-action@v5",
				Hash:       "2cdde995de11925a030ce8070c7d3a6e9e37440d",
				Algorithm:  "sha256",
				Canonical:  "docker/build-push-action@2cdde995de11925a030ce8070c7d3a6e9e37440d",
				Source:     "mock",
				ResolvedAt: now,
			},
		},
	}
}

func (m *mockResolver) Resolve(_ context.Context, reference string) (*resolver.Resolution, error) {
	r, ok := m.resolutions[reference]
	if !ok {
		return nil, fmt.Errorf("mock: unknown reference %q", reference)
	}
	return r, nil
}

func (m *mockResolver) Ecosystem() resolver.Ecosystem {
	return resolver.EcoGitHubAction
}

func testdataDir() string {
	return filepath.Join("..", "..", "internal", "testutil", "testdata")
}

func TestDiscoverWorkflows(t *testing.T) {
	paths, err := discoverWorkflows(testdataDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("expected at least one workflow file")
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) && !filepath.IsLocal(p) {
			// just verify they look like file paths
		}
		ext := filepath.Ext(p)
		if ext != ".yml" && ext != ".yaml" {
			t.Errorf("unexpected extension: %s", p)
		}
	}
}

func TestDiscoverWorkflows_MissingDir(t *testing.T) {
	_, err := discoverWorkflows("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestParseAndCollect(t *testing.T) {
	paths, err := discoverWorkflows(testdataDir())
	if err != nil {
		t.Fatal(err)
	}

	p := parser.NewWorkflowParser()
	workflows, err := parseWorkflows(p, paths)
	if err != nil {
		t.Fatal(err)
	}

	if len(workflows) == 0 {
		t.Fatal("expected at least one workflow")
	}

	tools := collectUniqueTools(workflows)
	if len(tools) == 0 {
		t.Fatal("expected at least one tool reference")
	}

	// ci.yml has: actions/checkout@v4, actions/setup-go@v5,
	// aquasecurity/trivy-action@v1, docker/build-push-action@v5
	if len(tools) != 4 {
		t.Errorf("expected 4 unique tools, got %d", len(tools))
		for ref := range tools {
			t.Logf("  tool: %s", ref)
		}
	}

	// Verify checkout appears once despite being in two steps.
	if _, ok := tools["actions/checkout@v4"]; !ok {
		t.Error("expected actions/checkout@v4 in tools")
	}
}

func TestResolveTools(t *testing.T) {
	tools := map[string]*parser.ToolRef{
		"actions/checkout@v4": {Reference: "actions/checkout@v4"},
		"actions/setup-go@v5": {Reference: "actions/setup-go@v5"},
	}

	mock := newMockResolver()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	resolved, err := resolveTools(ctx, logger, tools, mock)
	if err != nil {
		t.Fatal(err)
	}

	if len(resolved) != 2 {
		t.Fatalf("expected 2 resolutions, got %d", len(resolved))
	}

	r := resolved["actions/checkout@v4"]
	if r.Hash != "b4ffde65f46336ab88eb53be808477a3936bae11" {
		t.Errorf("unexpected hash: %s", r.Hash)
	}
}

func TestBuildLockfile(t *testing.T) {
	paths, err := discoverWorkflows(testdataDir())
	if err != nil {
		t.Fatal(err)
	}

	p := parser.NewWorkflowParser()
	workflows, err := parseWorkflows(p, paths)
	if err != nil {
		t.Fatal(err)
	}

	mock := newMockResolver()
	tools := collectUniqueTools(workflows)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	resolved, err := resolveTools(ctx, logger, tools, mock)
	if err != nil {
		t.Fatal(err)
	}

	lf := buildLockfile(workflows, resolved)

	if lf.Version != manifest.CurrentVersion {
		t.Errorf("expected version %d, got %d", manifest.CurrentVersion, lf.Version)
	}

	if len(lf.Pipelines) == 0 {
		t.Fatal("expected at least one pipeline")
	}

	// Verify it serializes to valid JSON.
	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty JSON output")
	}

	// Verify it round-trips.
	var lf2 manifest.Lockfile
	if err := json.Unmarshal(data, &lf2); err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if lf2.Version != lf.Version {
		t.Error("version mismatch after round-trip")
	}
}

func TestDoInit_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	lockfilePath := filepath.Join(tmpDir, "scg.lock")

	mock := newMockResolver()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	err := doInit(ctx, logger, testdataDir(), lockfilePath, mock)
	if err != nil {
		t.Fatal(err)
	}

	// Verify lockfile was written.
	if _, err := os.Stat(lockfilePath); err != nil {
		t.Fatalf("lockfile not written: %v", err)
	}

	// Read and verify lockfile.
	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		t.Fatal(err)
	}

	if lf.Version != manifest.CurrentVersion {
		t.Errorf("expected version %d, got %d", manifest.CurrentVersion, lf.Version)
	}

	if lf.Signature == nil {
		t.Error("expected lockfile to be signed")
	}
	if lf.Signature != nil && lf.Signature.Algorithm != "ed25519" && lf.Signature.Algorithm != "ed25519-platform" {
		t.Errorf("expected ed25519 or ed25519-platform signature, got %s", lf.Signature.Algorithm)
	}

	if len(lf.Pipelines) == 0 {
		t.Fatal("expected at least one pipeline")
	}

	// Count total tool entries across all steps.
	totalTools := 0
	for _, p := range lf.Pipelines {
		for _, s := range p.Steps {
			totalTools += len(s.Tools)
		}
	}

	// ci.yml: checkout (build), setup-go, trivy-action, checkout (publish), docker-push
	// = 5 tool entries (checkout appears in 2 steps)
	if totalTools < 4 {
		t.Errorf("expected at least 4 tool entries, got %d", totalTools)
	}

	// Verify signature is valid.
	err = manifest.VerifyLockfile(lf, &manifest.Ed25519Verifier{})
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestExtractBaseRef(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"actions/checkout@v4", "actions/checkout"},
		{"aquasecurity/trivy-action@v1", "aquasecurity/trivy-action"},
		{"docker/build-push-action@v5", "docker/build-push-action"},
		{"some-tool", "some-tool"},
		{"owner/repo@sha256:abc123", "owner/repo"},
	}

	for _, tt := range tests {
		got := extractBaseRef(tt.input)
		if got != tt.want {
			t.Errorf("extractBaseRef(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
