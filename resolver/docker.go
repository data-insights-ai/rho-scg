package resolver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DockerResolver resolves Docker image references to manifest digests
// using the Docker Registry HTTP API V2.
type DockerResolver struct {
	client *http.Client
}

// NewDockerResolver creates a Docker image resolver.
func NewDockerResolver() *DockerResolver {
	return &DockerResolver{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Ecosystem returns the Docker ecosystem.
func (r *DockerResolver) Ecosystem() Ecosystem {
	return EcoDocker
}

// Resolve resolves a Docker image reference to its manifest digest.
// Supports: image:tag, registry/image:tag, image@sha256:digest
func (r *DockerResolver) Resolve(ctx context.Context, reference string) (*Resolution, error) {
	registry, repo, tag, err := parseDockerRef(reference)
	if err != nil {
		return nil, err
	}

	// If already pinned to a digest, verify it exists.
	if strings.HasPrefix(tag, "sha256:") {
		return &Resolution{
			Original:   reference,
			Hash:       tag,
			Algorithm:  "sha256",
			Canonical:  fmt.Sprintf("%s/%s@%s", registry, repo, tag),
			Source:     registry,
			ResolvedAt: time.Now(),
		}, nil
	}

	// Resolve tag to digest via registry API.
	digest, err := r.resolveTag(ctx, registry, repo, tag)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", reference, err)
	}

	return &Resolution{
		Original:   reference,
		Hash:       digest,
		Algorithm:  "sha256",
		Canonical:  fmt.Sprintf("%s/%s@%s", registry, repo, digest),
		Source:     registry,
		ResolvedAt: time.Now(),
	}, nil
}

// resolveTag calls the Docker Registry V2 API to resolve a tag to a manifest digest.
func (r *DockerResolver) resolveTag(ctx context.Context, registry, repo, tag string) (string, error) {
	// Get auth token for Docker Hub.
	token, err := r.getToken(ctx, registry, repo)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repo, tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}

	// Accept manifest list or single manifest.
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned %d for %s/%s:%s", resp.StatusCode, registry, repo, tag)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no digest header for %s/%s:%s", registry, repo, tag)
	}

	return digest, nil
}

// getToken obtains an anonymous auth token for Docker Hub.
// For other registries, returns empty (no auth needed for public images).
func (r *DockerResolver) getToken(ctx context.Context, registry, repo string) (string, error) {
	if registry != "registry-1.docker.io" {
		return "", nil
	}

	url := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth token request failed: %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(resp, &result); err != nil {
		return "", err
	}

	return result.Token, nil
}

// parseDockerRef parses a Docker image reference into registry, repository, and tag.
func parseDockerRef(reference string) (registry, repo, tag string, err error) {
	// Handle digest references: image@sha256:...
	if atIdx := strings.Index(reference, "@"); atIdx >= 0 {
		imagePart := reference[:atIdx]
		tag = reference[atIdx+1:]
		registry, repo = splitRegistryRepo(imagePart)
		return registry, repo, tag, nil
	}

	// Handle tag references: image:tag
	imagePart := reference
	tag = "latest"

	if colonIdx := strings.LastIndex(reference, ":"); colonIdx >= 0 {
		potentialTag := reference[colonIdx+1:]
		potentialImage := reference[:colonIdx]
		// Disambiguate registry:port/image from image:tag.
		if !strings.Contains(potentialTag, "/") {
			imagePart = potentialImage
			tag = potentialTag
		}
	}

	registry, repo = splitRegistryRepo(imagePart)
	return registry, repo, tag, nil
}

// splitRegistryRepo splits an image name into registry and repository.
// Docker Hub images without a registry get "registry-1.docker.io" and "library/" prefix.
func splitRegistryRepo(image string) (registry, repo string) {
	parts := strings.SplitN(image, "/", 2)

	if len(parts) == 1 {
		// Official image: "alpine" → "registry-1.docker.io/library/alpine"
		return "registry-1.docker.io", "library/" + parts[0]
	}

	first := parts[0]
	// Check if first part looks like a registry (contains . or :).
	if strings.Contains(first, ".") || strings.Contains(first, ":") {
		return first, parts[1]
	}

	// Docker Hub user image: "user/image" → "registry-1.docker.io/user/image"
	return "registry-1.docker.io", image
}
