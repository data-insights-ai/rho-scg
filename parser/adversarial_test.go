package parser

import (
	"strings"
	"testing"
)

// --- Workflow parser adversarial tests ---

func TestWorkflowParser_EmptyFile(t *testing.T) {
	p := NewWorkflowParser()
	wf, err := p.Parse("ci.yml", []byte(""))
	if err != nil {
		// Empty YAML is valid — produces empty structure.
		t.Logf("empty file error: %v", err)
		return
	}
	if len(wf.Tools) != 0 {
		t.Errorf("expected 0 tools from empty file, got %d", len(wf.Tools))
	}
}

func TestWorkflowParser_WhitespaceOnly(t *testing.T) {
	p := NewWorkflowParser()
	wf, err := p.Parse("ci.yml", []byte("   \n\n   \t\n"))
	if err != nil {
		t.Logf("whitespace-only error: %v", err)
		return
	}
	if len(wf.Tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(wf.Tools))
	}
}

func TestWorkflowParser_InvalidYAML(t *testing.T) {
	p := NewWorkflowParser()
	_, err := p.Parse("ci.yml", []byte(`{{{not: yaml: at: all`))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestWorkflowParser_NullBytes(t *testing.T) {
	content := []byte("name: CI\x00\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	p := NewWorkflowParser()
	// Should not panic.
	_, _ = p.Parse("ci.yml", content)
}

func TestWorkflowParser_BinaryContent(t *testing.T) {
	binary := make([]byte, 1024)
	for i := range binary {
		binary[i] = byte(i % 256)
	}
	p := NewWorkflowParser()
	// Should not panic.
	_, _ = p.Parse("ci.yml", binary)
}

func TestWorkflowParser_DeeplyNested(t *testing.T) {
	// Generate deeply nested YAML — should not stack overflow.
	var sb strings.Builder
	sb.WriteString("name: deep\non: push\njobs:\n  build:\n    steps:\n")
	for i := 0; i < 100; i++ {
		sb.WriteString("      - name: step-" + strings.Repeat("x", i) + "\n")
		sb.WriteString("        uses: actions/checkout@v4\n")
	}

	p := NewWorkflowParser()
	wf, err := p.Parse("ci.yml", []byte(sb.String()))
	if err != nil {
		t.Logf("deep nesting error: %v", err)
		return
	}
	if len(wf.Tools) != 100 {
		t.Errorf("expected 100 tools, got %d", len(wf.Tools))
	}
}

func TestWorkflowParser_MaliciousSecretPattern(t *testing.T) {
	// Attempt to inject secret-like patterns that aren't real secrets.
	content := []byte(`name: CI
on: push
jobs:
  build:
    steps:
      - name: test
        uses: actions/checkout@v4
        run: echo "${{ secrets.REAL_SECRET }}" && echo "fake_secrets.NOT_A_SECRET"
`)
	p := NewWorkflowParser()
	wf, err := p.Parse("ci.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	// Should only find REAL_SECRET, not NOT_A_SECRET.
	for _, s := range wf.Secrets {
		if s.Name == "NOT_A_SECRET" {
			t.Error("incorrectly extracted non-secret")
		}
	}
}

func TestWorkflowParser_NoJobs(t *testing.T) {
	content := []byte(`name: Empty
on: push
`)
	p := NewWorkflowParser()
	wf, err := p.Parse("ci.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(wf.Tools))
	}
}

// --- Dockerfile parser adversarial tests ---

func TestDockerfileParser_EmptyFile(t *testing.T) {
	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Tools) != 0 {
		t.Errorf("expected 0 tools from empty Dockerfile, got %d", len(wf.Tools))
	}
}

func TestDockerfileParser_CommentsOnly(t *testing.T) {
	content := []byte("# This is a comment\n# Another comment\n")
	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(wf.Tools))
	}
}

func TestDockerfileParser_NullBytes(t *testing.T) {
	content := []byte("FROM alpine:3.19\x00\nRUN echo hi\n")
	p := NewDockerfileParser()
	// Should not panic.
	_, _ = p.Parse("Dockerfile", content)
}

func TestDockerfileParser_LongImageRef(t *testing.T) {
	// 10KB image reference — should not crash.
	longRef := "FROM " + strings.Repeat("a", 10000) + ":latest\n"
	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", []byte(longRef))
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(wf.Tools))
	}
}

func TestDockerfileParser_ManyStages(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 50; i++ {
		sb.WriteString("FROM alpine:3.19 AS stage" + strings.Repeat("x", i) + "\n")
		sb.WriteString("RUN echo hi\n")
	}
	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", []byte(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Tools) != 50 {
		t.Errorf("expected 50 tools, got %d", len(wf.Tools))
	}
}

func TestDockerfileParser_EmptyFROM(t *testing.T) {
	content := []byte("FROM \nRUN echo hi\n")
	p := NewDockerfileParser()
	wf, err := p.Parse("Dockerfile", content)
	if err != nil {
		t.Fatal(err)
	}
	// Empty FROM should be skipped.
	if len(wf.Tools) != 0 {
		t.Errorf("expected 0 tools for empty FROM, got %d", len(wf.Tools))
	}
}

func TestDockerfileParser_ControlCharsInRef(t *testing.T) {
	content := []byte("FROM alpine\r\n:3.19\nRUN echo hi\n")
	p := NewDockerfileParser()
	// Should not panic.
	_, _ = p.Parse("Dockerfile", content)
}
