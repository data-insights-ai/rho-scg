//go:build integration

package resolver

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Integration tests that hit real registries.
// Run with: go test -tags integration ./resolver/ -v -count=1
// These are excluded from normal CI to avoid network flakiness.

func TestDockerResolver_RealAlpine(t *testing.T) {
	r := NewDockerResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "alpine:3.19")
	if err != nil {
		t.Skipf("skipping (network error): %v", err)
	}

	if !strings.HasPrefix(res.Hash, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", res.Hash)
	}
	if len(res.Hash) < 71 { // "sha256:" + 64 hex chars
		t.Errorf("hash too short: %q", res.Hash)
	}
	if res.Source != "registry-1.docker.io" {
		t.Errorf("source = %q, want registry-1.docker.io", res.Source)
	}
	t.Logf("alpine:3.19 -> %s", res.Hash)
}

func TestDockerResolver_RealNginx(t *testing.T) {
	r := NewDockerResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "nginx:1.25")
	if err != nil {
		t.Skipf("skipping (network error): %v", err)
	}

	if !strings.HasPrefix(res.Hash, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", res.Hash)
	}
	t.Logf("nginx:1.25 -> %s", res.Hash)
}

func TestPyPIResolver_RealRequests(t *testing.T) {
	r := NewPyPIResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "requests==2.31.0")
	if err != nil {
		t.Skipf("skipping (network error): %v", err)
	}

	if res.Hash == "" {
		t.Error("empty hash")
	}
	if res.Algorithm != "sha256" {
		t.Errorf("algorithm = %q, want sha256", res.Algorithm)
	}
	if res.Source != "pypi.org" {
		t.Errorf("source = %q, want pypi.org", res.Source)
	}
	t.Logf("requests==2.31.0 -> %s", res.Hash)
}

func TestNPMResolver_RealExpress(t *testing.T) {
	r := NewNPMResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "express@4.18.2")
	if err != nil {
		t.Skipf("skipping (network error): %v", err)
	}

	if res.Hash == "" {
		t.Error("empty hash")
	}
	// npm returns sha512 integrity hashes.
	if res.Algorithm != "sha512" {
		t.Errorf("algorithm = %q, want sha512", res.Algorithm)
	}
	if res.Source != "registry.npmjs.org" {
		t.Errorf("source = %q, want registry.npmjs.org", res.Source)
	}
	t.Logf("express@4.18.2 -> %s", res.Hash[:40])
}
