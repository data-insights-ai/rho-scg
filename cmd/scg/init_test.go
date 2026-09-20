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

func testdataMultiDir() string {
	return filepath.Join("..", "..", "internal", "testutil", "testdata_multi")
}

// newMultiMockResolvers returns mock resolvers for all ecosystems used in testdata_multi.
func newMultiMockResolvers() map[resolver.Ecosystem]resolver.Resolver {
	now := time.Date(2026, 3, 28, 10, 0, 0, 0, time.UTC)
	ghMock := newMockResolver()

	npmMock := &mockResolver{
		resolutions: map[string]*resolver.Resolution{
			"ms@2.1.3": {
				Original: "ms@2.1.3", Hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
				Algorithm: "sha512", Source: "mock", ResolvedAt: now,
			},
			"uuid@11.1.0": {
				Original: "uuid@11.1.0", Hash: "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3",
				Algorithm: "sha512", Source: "mock", ResolvedAt: now,
			},
		},
	}

	pypiMock := &mockResolver{
		resolutions: map[string]*resolver.Resolution{
			"httpx@0.28.1": {
				Original: "httpx@0.28.1", Hash: "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d",
				Algorithm: "sha256", Source: "mock", ResolvedAt: now,
			},
			"boto3@1.34.0": {
				Original: "boto3@1.34.0", Hash: "6f5e4d3c2b1a6f5e4d3c2b1a6f5e4d3c",
				Algorithm: "sha256", Source: "mock", ResolvedAt: now,
			},
			"click@8.1.8": {
				Original: "click@8.1.8", Hash: "aabbccddaabbccddaabbccddaabbccdd",
				Algorithm: "sha256", Source: "mock", ResolvedAt: now,
			},
		},
	}

	return map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: ghMock,
		resolver.EcoNPM:          npmMock,
		resolver.EcoPyPI:         pypiMock,
	}
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
		// A discovered path must actually resolve to a readable file — that is
		// the property callers depend on, and it holds whether the scan root
		// was given as an absolute or a relative path.
		if _, err := os.Stat(p); err != nil {
			t.Errorf("discovered path %q is not readable: %v", p, err)
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
		"actions/checkout@v4": {Reference: "actions/checkout@v4", Ecosystem: "github_action"},
		"actions/setup-go@v5": {Reference: "actions/setup-go@v5", Ecosystem: "github_action"},
	}

	mock := newMockResolver()
	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: mock,
	}
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	resolved, err := resolveTools(ctx, logger, tools, resolvers)
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
	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: mock,
	}
	tools := collectUniqueTools(workflows)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	resolved, err := resolveTools(ctx, logger, tools, resolvers)
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
	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: mock,
	}
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	err := doInit(ctx, logger, testdataDir(), lockfilePath, resolvers, testSigner(t))
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

func TestDiscoverLockfiles(t *testing.T) {
	dir := t.TempDir()
	// Create lockfiles.
	for _, name := range []string{"package-lock.json", "requirements.txt", "Dockerfile"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// Create a non-lockfile that should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi"), 0644); err != nil {
		t.Fatal(err)
	}

	paths := discoverLockfiles(dir)
	if len(paths) != 3 {
		t.Fatalf("expected 3 lockfiles, got %d: %v", len(paths), paths)
	}
}

func TestDiscoverLockfiles_Empty(t *testing.T) {
	dir := t.TempDir()
	paths := discoverLockfiles(dir)
	if len(paths) != 0 {
		t.Errorf("expected 0 lockfiles, got %d", len(paths))
	}
}

func TestDiscoverLockfiles_NonexistentDir(t *testing.T) {
	paths := discoverLockfiles("/nonexistent/path")
	if len(paths) != 0 {
		t.Errorf("expected 0 lockfiles for missing dir, got %d", len(paths))
	}
}

func TestParseWithMultiParser(t *testing.T) {
	dir := t.TempDir()

	// Create a package-lock.json.
	npmContent := []byte(`{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/express":{"version":"4.21.0"}}}`)
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), npmContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Create a requirements.txt.
	pypiContent := []byte("requests==2.31.0\n")
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), pypiContent, 0644); err != nil {
		t.Fatal(err)
	}

	paths := []string{
		filepath.Join(dir, "package-lock.json"),
		filepath.Join(dir, "requirements.txt"),
	}

	parsers := []parser.Parser{
		parser.NewNPMPackageParser(),
		parser.NewPyPIRequirementsParser(),
		parser.NewDockerfileParser(),
	}

	results, err := parseWithMultiParser(parsers, paths)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	types := make(map[string]bool)
	for _, r := range results {
		types[r.Type] = true
	}
	if !types["npm"] {
		t.Error("expected npm parse result")
	}
	if !types["pypi"] {
		t.Error("expected pypi parse result")
	}
}

func TestDoInit_WithLockfiles(t *testing.T) {
	tmpDir := t.TempDir()
	lockfilePath := filepath.Join(tmpDir, "scg.lock")

	resolvers := newMultiMockResolvers()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	workflowDir := filepath.Join(testdataMultiDir(), ".github", "workflows")
	err := doInit(ctx, logger, workflowDir, lockfilePath, resolvers, testSigner(t))
	if err != nil {
		t.Fatal(err)
	}

	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		t.Fatal(err)
	}

	// Should have pipelines for: workflow, npm, pypi.
	if len(lf.Pipelines) < 3 {
		t.Errorf("expected at least 3 pipelines, got %d", len(lf.Pipelines))
		for _, p := range lf.Pipelines {
			t.Logf("  pipeline: %s (type=%s)", p.Path, p.Type)
		}
	}

	// Collect all ecosystem types.
	ecosystems := make(map[string]bool)
	for _, p := range lf.Pipelines {
		ecosystems[p.Type] = true
	}
	if !ecosystems["github_actions"] {
		t.Error("expected github_actions pipeline")
	}
	if !ecosystems["npm"] {
		t.Error("expected npm pipeline")
	}
	if !ecosystems["pypi"] {
		t.Error("expected pypi pipeline")
	}

	// Count total tools.
	totalTools := 0
	for _, p := range lf.Pipelines {
		for _, s := range p.Steps {
			totalTools += len(s.Tools)
		}
	}
	// 4 github actions + 2 npm + 3 pypi = 9 minimum (checkout appears in 2 steps = 5 + 2 + 3 = 10)
	if totalTools < 9 {
		t.Errorf("expected at least 9 total tool entries, got %d", totalTools)
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
