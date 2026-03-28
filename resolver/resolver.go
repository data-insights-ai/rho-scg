// Package resolver resolves mutable dependency references to immutable content digests.
package resolver

import (
	"context"
	"time"
)

// Ecosystem identifies a dependency ecosystem.
type Ecosystem string

const (
	EcoGitHubAction Ecosystem = "github_action"
	EcoDocker       Ecosystem = "docker"
	EcoPyPI         Ecosystem = "pypi"
	EcoNPM          Ecosystem = "npm"
	EcoGo           Ecosystem = "go"
	EcoHelm         Ecosystem = "helm"
)

// Resolution holds the result of resolving a reference to a digest.
type Resolution struct {
	// Original is the mutable reference as found in the config file.
	Original string

	// Hash is the immutable content digest (e.g. "abc123def456...").
	Hash string

	// Algorithm is the hash algorithm (e.g. "sha256", "sha512").
	Algorithm string

	// Canonical is the fully-qualified immutable reference
	// (e.g. "actions/checkout@abc123def456").
	Canonical string

	// Source identifies where the resolution was performed (e.g. "api.github.com").
	Source string

	// ResolvedAt is when the resolution was performed.
	ResolvedAt time.Time
}

// Resolver resolves a mutable dependency reference to an immutable content digest.
type Resolver interface {
	// Resolve takes a mutable reference and returns its immutable resolution.
	Resolve(ctx context.Context, reference string) (*Resolution, error)

	// Ecosystem returns which ecosystem this resolver handles.
	Ecosystem() Ecosystem
}
