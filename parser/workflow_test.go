package parser

import (
	"testing"
)

func TestWorkflowParser_Supports(t *testing.T) {
	p := NewWorkflowParser()

	tests := []struct {
		path string
		want bool
	}{
		{".github/workflows/ci.yml", true},
		{".github/workflows/deploy.yaml", true},
		{".github/workflows/test.YML", false}, // case sensitive
		{"Dockerfile", false},
		{"requirements.txt", false},
		{".github/actions/local/action.yml", false}, // not in workflows
	}

	for _, tt := range tests {
		if got := p.Supports(tt.path); got != tt.want {
			t.Errorf("Supports(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestWorkflowParser_Parse(t *testing.T) {
	content := []byte(`name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: test
        run: go test ./...
      - name: trivy
        uses: aquasecurity/trivy-action@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`)

	p := NewWorkflowParser()
	wf, err := p.Parse(".github/workflows/ci.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	if wf.Type != "github_actions" {
		t.Errorf("type = %q, want github_actions", wf.Type)
	}

	if len(wf.Tools) != 2 {
		t.Fatalf("tools count = %d, want 2", len(wf.Tools))
	}

	// Verify checkout ref.
	found := false
	for _, tool := range wf.Tools {
		if tool.Reference == "actions/checkout@v4" {
			found = true
			if tool.Owner != "actions" {
				t.Errorf("owner = %q, want actions", tool.Owner)
			}
			if tool.Name != "checkout" {
				t.Errorf("name = %q, want checkout", tool.Name)
			}
		}
	}
	if !found {
		t.Error("actions/checkout@v4 not found in tools")
	}

	// Verify secrets.
	if len(wf.Secrets) != 1 {
		t.Fatalf("secrets count = %d, want 1", len(wf.Secrets))
	}
	if wf.Secrets[0].Name != "GITHUB_TOKEN" {
		t.Errorf("secret name = %q, want GITHUB_TOKEN", wf.Secrets[0].Name)
	}
}

func TestWorkflowParser_Parse_SkipsLocalActions(t *testing.T) {
	content := []byte(`name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
      - uses: docker://alpine:3.18
      - uses: actions/checkout@v4
`)

	p := NewWorkflowParser()
	wf, err := p.Parse("ci.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	// Only checkout should be parsed (local and docker:// skipped).
	if len(wf.Tools) != 1 {
		t.Fatalf("tools count = %d, want 1 (only checkout)", len(wf.Tools))
	}
	if wf.Tools[0].Reference != "actions/checkout@v4" {
		t.Errorf("tool = %q, want actions/checkout@v4", wf.Tools[0].Reference)
	}
}

func TestWorkflowParser_Parse_MultipleSecrets(t *testing.T) {
	content := []byte(`name: CI
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: push
        uses: docker/build-push-action@v5
        with:
          password: ${{ secrets.DOCKER_TOKEN }}
        env:
          AWS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
`)

	p := NewWorkflowParser()
	wf, err := p.Parse("ci.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Secrets) != 2 {
		t.Fatalf("secrets count = %d, want 2", len(wf.Secrets))
	}

	names := map[string]bool{}
	for _, s := range wf.Secrets {
		names[s.Name] = true
	}
	if !names["DOCKER_TOKEN"] {
		t.Error("missing DOCKER_TOKEN")
	}
	if !names["AWS_SECRET_ACCESS_KEY"] {
		t.Error("missing AWS_SECRET_ACCESS_KEY")
	}
}
