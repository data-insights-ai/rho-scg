package manifest

import (
	"context"
	"testing"
	"time"

	"github.com/data-insights-ai/rho-scg/resolver"
)

type fixedResolver struct {
	hash string
}

func (r *fixedResolver) Resolve(_ context.Context, _ string) (*resolver.Resolution, error) {
	return &resolver.Resolution{
		Hash:       r.hash,
		Algorithm:  "sha256",
		Source:     "test",
		ResolvedAt: time.Now(),
	}, nil
}

func (r *fixedResolver) Ecosystem() resolver.Ecosystem {
	return resolver.EcoGitHubAction
}

func TestDetectDrift_NoDrift(t *testing.T) {
	lf := &Lockfile{
		Pipelines: []PipelineEntry{
			{
				Steps: []StepEntry{
					{
						Tools: []ToolEntry{
							{Ecosystem: "github_action", Reference: "actions/checkout@v4", Hash: "abc123"},
						},
					},
				},
			},
		},
	}

	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: &fixedResolver{hash: "abc123"},
	}

	results, err := DetectDrift(context.Background(), lf, resolvers)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no drift, got %d", len(results))
	}
}

func TestDetectDrift_DriftDetected(t *testing.T) {
	lf := &Lockfile{
		Pipelines: []PipelineEntry{
			{
				Steps: []StepEntry{
					{
						Tools: []ToolEntry{
							{Ecosystem: "github_action", Reference: "actions/checkout@v4", Hash: "locked_hash"},
						},
					},
				},
			},
		},
	}

	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: &fixedResolver{hash: "different_hash"},
	}

	results, err := DetectDrift(context.Background(), lf, resolvers)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 drift, got %d", len(results))
	}
	if results[0].Severity != SevCritical {
		t.Errorf("severity = %s, want CRITICAL", results[0].Severity)
	}
	if results[0].LockedHash != "locked_hash" {
		t.Errorf("locked = %q", results[0].LockedHash)
	}
	if results[0].LiveHash != "different_hash" {
		t.Errorf("live = %q", results[0].LiveHash)
	}
}

func TestDetectDrift_UnknownEcosystem(t *testing.T) {
	lf := &Lockfile{
		Pipelines: []PipelineEntry{
			{
				Steps: []StepEntry{
					{
						Tools: []ToolEntry{
							{Ecosystem: "docker", Reference: "alpine:3.18", Hash: "abc"},
						},
					},
				},
			},
		},
	}

	// No Docker resolver registered — should skip silently.
	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: &fixedResolver{hash: "abc"},
	}

	results, err := DetectDrift(context.Background(), lf, resolvers)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no drift (unknown eco skipped), got %d", len(results))
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{SevInfo, "INFO"},
		{SevWarning, "WARNING"},
		{SevCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}
