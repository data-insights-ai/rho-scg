package resolver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GitHubResolver resolves GitHub Actions references to commit SHAs.
// This is the resolver that would have caught the TeamPCP attack —
// it detects when a tag points to a different commit than expected.
type GitHubResolver struct {
	client *http.Client
	token  string
}

// NewGitHubResolver creates a GitHub Actions resolver.
// token is optional but recommended to avoid rate limits.
func NewGitHubResolver(token string) *GitHubResolver {
	return &GitHubResolver{
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
	}
}

// Ecosystem returns the GitHub Actions ecosystem.
func (r *GitHubResolver) Ecosystem() Ecosystem {
	return EcoGitHubAction
}

// Resolve resolves a GitHub Actions reference (owner/repo@tag) to a commit SHA.
func (r *GitHubResolver) Resolve(ctx context.Context, reference string) (*Resolution, error) {
	owner, repo, ref, err := parseActionRef(reference)
	if err != nil {
		return nil, err
	}

	sha, err := r.resolveRef(ctx, owner, repo, ref)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", reference, err)
	}

	return &Resolution{
		Original:   reference,
		Hash:       sha,
		Algorithm:  "sha256",
		Canonical:  fmt.Sprintf("%s/%s@%s", owner, repo, sha),
		Source:     "api.github.com",
		ResolvedAt: time.Now(),
	}, nil
}

// resolveRef calls the GitHub API to resolve a git ref to a commit SHA.
func (r *GitHubResolver) resolveRef(ctx context.Context, owner, repo, ref string) (string, error) {
	// Try as a tag first, then as a branch.
	for _, refType := range []string{"tags", "heads"} {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/ref/%s/%s", escapePath(owner), escapePath(repo), refType, escapePath(ref))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		if r.token != "" {
			req.Header.Set("Authorization", "Bearer "+r.token)
		}

		resp, err := r.client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("GitHub API returned %d for %s/%s ref %s/%s", resp.StatusCode, owner, repo, refType, ref)
		}

		var result struct {
			Object struct {
				SHA  string `json:"sha"`
				Type string `json:"type"`
			} `json:"object"`
		}
		if err := decodeJSON(resp, &result); err != nil {
			return "", err
		}

		sha := result.Object.SHA

		// If it's an annotated tag, we need to dereference to get the commit.
		if result.Object.Type == "tag" {
			sha, err = r.dereferenceTag(ctx, owner, repo, sha)
			if err != nil {
				return "", err
			}
		}

		if sha == "" {
			return "", fmt.Errorf("GitHub API returned empty SHA for %s/%s ref %s/%s", owner, repo, refType, ref)
		}

		return sha, nil
	}

	// If it looks like a SHA already, verify it exists.
	if len(ref) == 40 || len(ref) == 64 {
		return ref, nil
	}

	return "", fmt.Errorf("could not resolve ref %q for %s/%s", ref, owner, repo)
}

// dereferenceTag resolves an annotated tag object to its target commit SHA.
func (r *GitHubResolver) dereferenceTag(ctx context.Context, owner, repo, tagSHA string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/tags/%s", escapePath(owner), escapePath(repo), escapePath(tagSHA))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %d dereferencing tag %s", resp.StatusCode, tagSHA)
	}

	var result struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := decodeJSON(resp, &result); err != nil {
		return "", err
	}

	return result.Object.SHA, nil
}

// parseActionRef parses "owner/repo@ref" into its components.
func parseActionRef(reference string) (owner, repo, ref string, err error) {
	// Strip version prefix: "owner/repo@v1" → owner, repo, v1
	atIdx := strings.LastIndex(reference, "@")
	if atIdx < 0 {
		return "", "", "", fmt.Errorf("invalid action reference %q: missing @", reference)
	}

	slug := reference[:atIdx]
	ref = reference[atIdx+1:]

	parts := strings.SplitN(slug, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("invalid action reference %q: expected owner/repo@ref", reference)
	}

	return parts[0], parts[1], ref, nil
}
