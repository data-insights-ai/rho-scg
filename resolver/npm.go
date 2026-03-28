package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// NPMResolver resolves npm package versions to integrity hashes
// using the npm registry API.
type NPMResolver struct {
	client *http.Client
}

// NewNPMResolver creates an npm package resolver.
func NewNPMResolver() *NPMResolver {
	return &NPMResolver{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Ecosystem returns the npm ecosystem.
func (r *NPMResolver) Ecosystem() Ecosystem {
	return EcoNPM
}

// Resolve resolves an npm package reference (name@version) to its integrity hash.
func (r *NPMResolver) Resolve(ctx context.Context, reference string) (*Resolution, error) {
	name, version, err := parseNPMRef(reference)
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
		Algorithm:  "sha512",
		Canonical:  fmt.Sprintf("%s@%s@%s", name, version, hash),
		Source:     "registry.npmjs.org",
		ResolvedAt: time.Now(),
	}, nil
}

// resolveVersion fetches the integrity hash for a specific npm package version.
func (r *NPMResolver) resolveVersion(ctx context.Context, name, version string) (string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", name, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package %s version %s not found on npm", name, version)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("npm registry returned %d for %s@%s", resp.StatusCode, name, version)
	}

	var result npmVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode npm response: %w", err)
	}

	if result.Dist.Integrity != "" {
		return result.Dist.Integrity, nil
	}
	if result.Dist.Shasum != "" {
		return "sha1:" + result.Dist.Shasum, nil
	}

	return "", fmt.Errorf("no integrity hash found for %s@%s", name, version)
}

type npmVersionResponse struct {
	Dist struct {
		Integrity string `json:"integrity"`
		Shasum    string `json:"shasum"`
	} `json:"dist"`
}

// parseNPMRef parses "package@version" into name and version.
func parseNPMRef(reference string) (name, version string, err error) {
	// Handle scoped packages: @scope/package@version.
	if strings.HasPrefix(reference, "@") {
		// Find the second @ which separates name from version.
		rest := reference[1:]
		atIdx := strings.Index(rest, "@")
		if atIdx < 0 {
			return "", "", fmt.Errorf("invalid npm reference %q: expected @scope/name@version", reference)
		}
		return reference[:atIdx+1], rest[atIdx+1:], nil
	}

	parts := strings.SplitN(reference, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid npm reference %q: expected name@version", reference)
	}
	return parts[0], parts[1], nil
}
