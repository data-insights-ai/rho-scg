package resolver

import "testing"

func TestParseActionRef(t *testing.T) {
	tests := []struct {
		input     string
		owner     string
		repo      string
		ref       string
		expectErr bool
	}{
		{"actions/checkout@v4", "actions", "checkout", "v4", false},
		{"aquasecurity/trivy-action@v1", "aquasecurity", "trivy-action", "v1", false},
		{"docker/build-push-action@v5", "docker", "build-push-action", "v5", false},
		{"owner/repo@sha256:abc123", "owner", "repo", "sha256:abc123", false},
		{"owner/repo@abc123def456", "owner", "repo", "abc123def456", false},
		{"no-at-sign", "", "", "", true},
		{"@v1", "", "", "", true},
		{"/repo@v1", "", "", "", true},
		{"owner/@v1", "", "", "", true},
	}

	for _, tt := range tests {
		owner, repo, ref, err := parseActionRef(tt.input)
		if tt.expectErr {
			if err == nil {
				t.Errorf("parseActionRef(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseActionRef(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if owner != tt.owner {
			t.Errorf("parseActionRef(%q) owner = %q, want %q", tt.input, owner, tt.owner)
		}
		if repo != tt.repo {
			t.Errorf("parseActionRef(%q) repo = %q, want %q", tt.input, repo, tt.repo)
		}
		if ref != tt.ref {
			t.Errorf("parseActionRef(%q) ref = %q, want %q", tt.input, ref, tt.ref)
		}
	}
}

func TestEcosystemConstants(t *testing.T) {
	// Verify ecosystem constants are not empty.
	ecosystems := []Ecosystem{
		EcoGitHubAction, EcoDocker, EcoPyPI, EcoNPM, EcoGo, EcoHelm,
	}
	for _, eco := range ecosystems {
		if eco == "" {
			t.Error("empty ecosystem constant")
		}
	}
}

func TestNewGitHubResolver(t *testing.T) {
	r := NewGitHubResolver("test-token")
	if r.Ecosystem() != EcoGitHubAction {
		t.Errorf("ecosystem = %q, want %q", r.Ecosystem(), EcoGitHubAction)
	}
	if r.token != "test-token" {
		t.Errorf("token not set")
	}
}

func TestNewGitHubResolver_NoToken(t *testing.T) {
	r := NewGitHubResolver("")
	if r.token != "" {
		t.Errorf("token should be empty")
	}
}
