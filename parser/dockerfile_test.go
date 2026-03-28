package parser

import "testing"

func TestDockerfileParser_Supports(t *testing.T) {
	p := NewDockerfileParser()

	tests := []struct {
		path string
		want bool
	}{
		{"Dockerfile", true},
		{"dockerfile", true},
		{"app.Dockerfile", true},
		{"app.dockerfile", true},
		{"Dockerfile.prod", true},
		{".github/workflows/ci.yml", false},
		{"requirements.txt", false},
	}

	for _, tt := range tests {
		if got := p.Supports(tt.path); got != tt.want {
			t.Errorf("Supports(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestDockerfileParser_Parse(t *testing.T) {
	content := []byte(`# Build stage
FROM golang:1.22-alpine AS builder
RUN go build -o app

# Runtime stage
FROM alpine:3.19
COPY --from=builder /app /app
CMD ["/app"]
`)

	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", content)
	if err != nil {
		t.Fatal(err)
	}

	if wf.Type != "docker" {
		t.Errorf("type = %q, want docker", wf.Type)
	}

	if len(wf.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(wf.Tools))
	}

	// First FROM: golang:1.22-alpine.
	if wf.Tools[0].Reference != "golang:1.22-alpine" {
		t.Errorf("tool[0].ref = %q, want golang:1.22-alpine", wf.Tools[0].Reference)
	}
	if wf.Tools[0].Version != "1.22-alpine" {
		t.Errorf("tool[0].version = %q, want 1.22-alpine", wf.Tools[0].Version)
	}

	// Second FROM: alpine:3.19.
	if wf.Tools[1].Reference != "alpine:3.19" {
		t.Errorf("tool[1].ref = %q, want alpine:3.19", wf.Tools[1].Reference)
	}

	// Check stage names.
	if len(wf.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(wf.Steps))
	}
	if wf.Steps[0].Name != "builder" {
		t.Errorf("step[0].name = %q, want builder", wf.Steps[0].Name)
	}
	if wf.Steps[1].Name != "stage-1" {
		t.Errorf("step[1].name = %q, want stage-1", wf.Steps[1].Name)
	}
}

func TestDockerfileParser_SkipsScratch(t *testing.T) {
	content := []byte(`FROM golang:1.22 AS builder
FROM scratch
COPY --from=builder /app /app
`)

	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 1 {
		t.Fatalf("tools = %d, want 1 (scratch skipped)", len(wf.Tools))
	}
}

func TestDockerfileParser_RegistryImage(t *testing.T) {
	content := []byte(`FROM ghcr.io/aquasecurity/trivy:0.50.0
`)

	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 1 {
		t.Fatalf("tools = %d, want 1", len(wf.Tools))
	}
	if wf.Tools[0].Owner != "ghcr.io/aquasecurity" {
		t.Errorf("owner = %q", wf.Tools[0].Owner)
	}
	if wf.Tools[0].Version != "0.50.0" {
		t.Errorf("version = %q, want 0.50.0", wf.Tools[0].Version)
	}
}

func TestDockerfileParser_DigestRef(t *testing.T) {
	content := []byte(`FROM alpine@sha256:abc123def456
`)

	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 1 {
		t.Fatalf("tools = %d, want 1", len(wf.Tools))
	}
	if wf.Tools[0].Version != "sha256:abc123def456" {
		t.Errorf("version = %q, want sha256:abc123def456", wf.Tools[0].Version)
	}
}

func TestDockerfileParser_SkipsBuildArgs(t *testing.T) {
	content := []byte(`ARG BASE=alpine
FROM ${BASE}:latest
FROM golang:1.22
`)

	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", content)
	if err != nil {
		t.Fatal(err)
	}

	// Build arg FROM skipped, only golang parsed.
	if len(wf.Tools) != 1 {
		t.Fatalf("tools = %d, want 1 (build arg skipped)", len(wf.Tools))
	}
	if wf.Tools[0].Name != "golang" {
		t.Errorf("name = %q, want golang", wf.Tools[0].Name)
	}
}
