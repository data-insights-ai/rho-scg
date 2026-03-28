package resolver

import "testing"

func TestParseDockerRef(t *testing.T) {
	tests := []struct {
		input    string
		registry string
		repo     string
		tag      string
	}{
		{"alpine:3.19", "registry-1.docker.io", "library/alpine", "3.19"},
		{"alpine", "registry-1.docker.io", "library/alpine", "latest"},
		{"nginx:latest", "registry-1.docker.io", "library/nginx", "latest"},
		{"user/app:v1", "registry-1.docker.io", "user/app", "v1"},
		{"ghcr.io/owner/image:tag", "ghcr.io", "owner/image", "tag"},
		{"registry.example.com:5000/myapp:v2", "registry.example.com:5000", "myapp", "v2"},
		{"alpine@sha256:abc123", "registry-1.docker.io", "library/alpine", "sha256:abc123"},
		{"ghcr.io/org/img@sha256:def456", "ghcr.io", "org/img", "sha256:def456"},
	}

	for _, tt := range tests {
		registry, repo, tag, err := parseDockerRef(tt.input)
		if err != nil {
			t.Errorf("parseDockerRef(%q) error: %v", tt.input, err)
			continue
		}
		if registry != tt.registry {
			t.Errorf("parseDockerRef(%q) registry = %q, want %q", tt.input, registry, tt.registry)
		}
		if repo != tt.repo {
			t.Errorf("parseDockerRef(%q) repo = %q, want %q", tt.input, repo, tt.repo)
		}
		if tag != tt.tag {
			t.Errorf("parseDockerRef(%q) tag = %q, want %q", tt.input, tag, tt.tag)
		}
	}
}

func TestSplitRegistryRepo(t *testing.T) {
	tests := []struct {
		image    string
		registry string
		repo     string
	}{
		{"alpine", "registry-1.docker.io", "library/alpine"},
		{"user/app", "registry-1.docker.io", "user/app"},
		{"ghcr.io/owner/image", "ghcr.io", "owner/image"},
		{"localhost:5000/myapp", "localhost:5000", "myapp"},
	}

	for _, tt := range tests {
		registry, repo := splitRegistryRepo(tt.image)
		if registry != tt.registry {
			t.Errorf("splitRegistryRepo(%q) registry = %q, want %q", tt.image, registry, tt.registry)
		}
		if repo != tt.repo {
			t.Errorf("splitRegistryRepo(%q) repo = %q, want %q", tt.image, repo, tt.repo)
		}
	}
}

func TestNewDockerResolver(t *testing.T) {
	r := NewDockerResolver()
	if r.Ecosystem() != EcoDocker {
		t.Errorf("ecosystem = %q, want %q", r.Ecosystem(), EcoDocker)
	}
}
