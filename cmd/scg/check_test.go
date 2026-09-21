package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/resolver"
)

func TestDoCheck_Clean(t *testing.T) {
	// Init with mock resolver, then check — should find no drift
	// since the mock returns the same hashes.
	tmpDir := t.TempDir()
	lockfilePath := filepath.Join(tmpDir, "scg.lock")

	mock := newMockResolver()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	if err := doInit(ctx, logger, "", testdataDir(), lockfilePath, map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: mock}, testSigner(t)); err != nil {
		t.Fatal(err)
	}

	// doCheck calls the real GitHub resolver, so we can't easily inject a mock.
	// Instead, verify the lockfile is valid and check drift directly.
	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature.
	if err := manifest.VerifyLockfile(lf, &manifest.Ed25519Verifier{}); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// Check drift with same mock resolver — should be clean.
	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: mock,
	}
	results, err := manifest.DetectDrift(ctx, lf, resolvers)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) > 0 {
		t.Fatalf("expected no drift, got %d result(s)", len(results))
	}
}

func TestDoCheck_DriftDetected(t *testing.T) {
	// Init with mock, tamper lockfile, then detect drift with the same mock.
	// The mock returns the original hash; the lockfile has a tampered hash.
	// This simulates: attacker rewrites tag → digest changes → SCG catches it.
	tmpDir := t.TempDir()
	lockfilePath := filepath.Join(tmpDir, "scg.lock")

	mock := newMockResolver()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	if err := doInit(ctx, logger, "", testdataDir(), lockfilePath, map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: mock}, testSigner(t)); err != nil {
		t.Fatal(err)
	}

	// Tamper the lockfile: replace checkout's hash with a fake one.
	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		t.Fatal(err)
	}
	lf.Signature = nil // remove signature (would fail after tampering)

	tampered := false
	for i := range lf.Pipelines {
		for j := range lf.Pipelines[i].Steps {
			for k := range lf.Pipelines[i].Steps[j].Tools {
				te := &lf.Pipelines[i].Steps[j].Tools[k]
				if te.Reference == "actions/checkout@v4" {
					te.Hash = "ff00bad1337cafe0000000000000000000000000"
					tampered = true
				}
			}
		}
	}
	if !tampered {
		t.Fatal("could not find actions/checkout@v4 to tamper")
	}

	if err := manifest.WriteLockfile(lockfilePath, lf); err != nil {
		t.Fatal(err)
	}

	// Detect drift: mock returns the original hash, lockfile has the tampered one.
	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: mock,
	}
	results, driftErr := manifest.DetectDrift(ctx, lf, resolvers)
	if driftErr != nil {
		t.Fatal(driftErr)
	}

	if len(results) == 0 {
		t.Fatal("expected drift to be detected, got none")
	}

	// Find the checkout drift result.
	found := false
	for _, d := range results {
		if d.Reference == "actions/checkout@v4" {
			found = true
			if d.Severity != manifest.SevCritical {
				t.Errorf("expected CRITICAL severity, got %s", d.Severity)
			}
			if d.LockedHash != "ff00bad1337cafe0000000000000000000000000" {
				t.Errorf("locked hash mismatch: %s", d.LockedHash)
			}
			if d.LiveHash != "b4ffde65f46336ab88eb53be808477a3936bae11" {
				t.Errorf("live hash mismatch: %s", d.LiveHash)
			}
			t.Logf("Drift detected: %s", d.Detail)
		}
	}
	if !found {
		t.Error("drift for actions/checkout@v4 not found in results")
	}
}

func TestDoCheck_DriftDetected_MultipleTools(t *testing.T) {
	// Tamper two tools and verify both are detected.
	tmpDir := t.TempDir()
	lockfilePath := filepath.Join(tmpDir, "scg.lock")

	mock := newMockResolver()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	if err := doInit(ctx, logger, "", testdataDir(), lockfilePath, map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: mock}, testSigner(t)); err != nil {
		t.Fatal(err)
	}

	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		t.Fatal(err)
	}
	lf.Signature = nil

	// Tamper both checkout and setup-go.
	for i := range lf.Pipelines {
		for j := range lf.Pipelines[i].Steps {
			for k := range lf.Pipelines[i].Steps[j].Tools {
				te := &lf.Pipelines[i].Steps[j].Tools[k]
				switch te.Reference {
				case "actions/checkout@v4":
					te.Hash = "aaaa000000000000000000000000000000000000"
				case "actions/setup-go@v5":
					te.Hash = "bbbb000000000000000000000000000000000000"
				}
			}
		}
	}

	if err := manifest.WriteLockfile(lockfilePath, lf); err != nil {
		t.Fatal(err)
	}

	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: mock,
	}
	results, err := manifest.DetectDrift(ctx, lf, resolvers)
	if err != nil {
		t.Fatal(err)
	}

	// Both should be detected. The actual count may be higher if checkout
	// appears in multiple steps (each step entry is checked independently).
	if len(results) < 2 {
		t.Errorf("expected at least 2 drift results, got %d", len(results))
	}

	refs := make(map[string]bool)
	for _, d := range results {
		refs[d.Reference] = true
	}
	if !refs["actions/checkout@v4"] {
		t.Error("missing drift for actions/checkout@v4")
	}
	if !refs["actions/setup-go@v5"] {
		t.Error("missing drift for actions/setup-go@v5")
	}
}

// driftResolver returns a different hash for one specific tool to simulate hijack.
type driftResolver struct {
	original *mockResolver
	hijacked string
	fakeHash string
}

func (r *driftResolver) Resolve(ctx context.Context, reference string) (*resolver.Resolution, error) {
	if reference == r.hijacked {
		return &resolver.Resolution{
			Original:   reference,
			Hash:       r.fakeHash,
			Algorithm:  "sha256",
			Source:     "mock-hijacked",
			ResolvedAt: time.Now(),
		}, nil
	}
	return r.original.Resolve(ctx, reference)
}

func (r *driftResolver) Ecosystem() resolver.Ecosystem {
	return resolver.EcoGitHubAction
}
