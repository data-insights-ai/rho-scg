package resolver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PyPIResolver resolves PyPI package versions to content hashes
// using the PyPI JSON API.
type PyPIResolver struct {
	client *http.Client
}

// NewPyPIResolver creates a PyPI package resolver.
func NewPyPIResolver() *PyPIResolver {
	return &PyPIResolver{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Ecosystem returns the PyPI ecosystem.
func (r *PyPIResolver) Ecosystem() Ecosystem {
	return EcoPyPI
}

// Resolve resolves a PyPI package reference (name==version) to its content hash.
func (r *PyPIResolver) Resolve(ctx context.Context, reference string) (*Resolution, error) {
	name, version, err := parsePyPIRef(reference)
	if err != nil {
		return nil, err
	}

	hash, err := r.resolveVersion(ctx, name, version)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", reference, err)
	}

	return &Resolution{
		Original:   reference,
		Hash:       hash,
		Algorithm:  "sha256",
		Canonical:  fmt.Sprintf("%s==%s@%s", name, version, hash),
		Source:     "pypi.org",
		ResolvedAt: time.Now(),
	}, nil
}

// resolveVersion fetches the SHA256 hash for a specific PyPI package version.
func (r *PyPIResolver) resolveVersion(ctx context.Context, name, version string) (string, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", escapePath(name), escapePath(version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package %s version %s not found on PyPI", name, version)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PyPI API returned %d for %s==%s", resp.StatusCode, name, version)
	}

	var result pypiResponse
	if err := decodeJSON(resp, &result); err != nil {
		return "", err
	}

	// Find the sdist or first wheel with a sha256 digest.
	for _, files := range result.URLs {
		if hash, ok := files.Digests["sha256"]; ok && hash != "" {
			return hash, nil
		}
	}

	return "", fmt.Errorf("no sha256 digest found for %s==%s", name, version)
}

type pypiResponse struct {
	URLs []pypiFile `json:"urls"`
}

type pypiFile struct {
	Digests     map[string]string `json:"digests"`
	PackageType string            `json:"packagetype"`
}

// parsePyPIRef parses "package==version" or "package>=version" into name and version.
func parsePyPIRef(reference string) (name, version string, err error) {
	// Handle == (exact pin).
	if parts := strings.SplitN(reference, "==", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	}
	// Handle >= (minimum version — resolve to the specified version).
	if parts := strings.SplitN(reference, ">=", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	}
	return "", "", fmt.Errorf("invalid PyPI reference %q: expected name==version", reference)
}
