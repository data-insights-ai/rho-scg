package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/resolver"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// lockfileWith builds a lockfile in which the same references appear across
// several steps, which is what a real workflow produces.
func lockfileWith(entries ...manifest.ToolEntry) *manifest.Lockfile {
	steps := make([]manifest.StepEntry, 0, len(entries))
	for i, e := range entries {
		steps = append(steps, manifest.StepEntry{
			Name:  "step",
			Order: i,
			Tools: []manifest.ToolEntry{e},
		})
	}
	return &manifest.Lockfile{
		Version:   manifest.CurrentVersion,
		Pipelines: []manifest.PipelineEntry{{Path: "ci.yml", Type: "github_actions", Steps: steps}},
	}
}

// countingResolver records how many times the network was actually touched.
type countingResolver struct {
	calls atomic.Int32
	hash  string
	stale bool
	age   time.Duration
	err   error
}

func (r *countingResolver) Ecosystem() resolver.Ecosystem { return resolver.EcoGitHubAction }

func (r *countingResolver) Resolve(_ context.Context, ref string) (*resolver.Resolution, error) {
	r.calls.Add(1)
	if r.err != nil {
		return nil, r.err
	}
	return &resolver.Resolution{Original: ref, Hash: r.hash, Algorithm: "sha1", Source: "test"}, nil
}

func (r *countingResolver) Freshness(string) (bool, time.Duration) { return r.stale, r.age }

// The lockfile records one entry per step, so a single action used in four
// steps was resolved four times — four requests to ask one question, against a
// budget of twenty an hour.
func TestDetectDrift_ResolvesEachReferenceOnce(t *testing.T) {
	entry := manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "actions/checkout@v4",
		Hash: "abc123", Algorithm: "sha1",
	}
	lf := lockfileWith(entry, entry, entry, entry)

	r := &countingResolver{hash: "abc123"}
	_, warnings, err := detectDriftWithPartialFailure(context.Background(), lf,
		map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: r}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if got := r.calls.Load(); got != 1 {
		t.Errorf("resolved %d times for 4 entries of one reference, want 1", got)
	}
}

// Every entry must still be compared, even though each reference is resolved
// once — deduplicating the requests must not deduplicate the findings.
func TestDetectDrift_ComparesEveryEntry(t *testing.T) {
	entry := manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "actions/checkout@v4",
		Hash: "locked-hash", Algorithm: "sha1",
	}
	lf := lockfileWith(entry, entry, entry)

	r := &countingResolver{hash: "different-hash"}
	drift, _, err := detectDriftWithPartialFailure(context.Background(), lf,
		map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: r}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 3 {
		t.Errorf("found %d drift results, want 3 (one per entry)", len(drift))
	}
}

// A stale answer matching a stale lockfile is not evidence: both sides came
// from the same unrefreshed record. Reporting it as verified is exactly how a
// green check appeared over references that had in fact moved.
func TestDetectDrift_StaleDataIsNotVerified(t *testing.T) {
	entry := manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "actions/checkout@v4",
		Hash: "abc123", Algorithm: "sha1",
	}
	lf := lockfileWith(entry)

	r := &countingResolver{hash: "abc123", stale: true, age: 72 * time.Hour}
	drift, warnings, err := detectDriftWithPartialFailure(context.Background(), lf,
		map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: r}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 0 {
		t.Error("stale data must not be reported as drift — nothing was actually compared")
	}
	if len(warnings) != 1 {
		t.Fatalf("stale data must produce a warning, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "stale") {
		t.Errorf("warning should say the data is stale, got: %q", warnings[0])
	}
}

// A hijacked tag is the attack this product exists to catch.
func TestDetectDrift_DetectsHijackedTag(t *testing.T) {
	mock := newMockResolver()
	hijack := &driftResolver{
		original: mock,
		hijacked: "actions/checkout@v4",
		fakeHash: "0000000000000000000000000000000000000000",
	}

	lf := lockfileWith(
		manifest.ToolEntry{Ecosystem: "github_action", Reference: "actions/checkout@v4",
			Hash: "b4ffde65f46336ab88eb53be808477a3936bae11", Algorithm: "sha1"},
		manifest.ToolEntry{Ecosystem: "github_action", Reference: "actions/setup-go@v5",
			Hash: "0aaccfd150a27a34a12cf405e5a1e58deff3170e", Algorithm: "sha1"},
	)

	drift, warnings, err := detectDriftWithPartialFailure(context.Background(), lf,
		map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: hijack}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(drift) != 1 {
		t.Fatalf("found %d drift results, want exactly 1", len(drift))
	}
	if drift[0].Reference != "actions/checkout@v4" {
		t.Errorf("drift reported on %q, want actions/checkout@v4", drift[0].Reference)
	}
	if drift[0].Severity != manifest.SevCritical {
		t.Errorf("a hijacked tag must be critical, got %v", drift[0].Severity)
	}
}

// A resolver failure is a warning, not an abort: one broken reference must not
// hide the state of every other one.
func TestDetectDrift_ResolverFailureBecomesWarning(t *testing.T) {
	lf := lockfileWith(manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "actions/checkout@v4",
		Hash: "abc", Algorithm: "sha1",
	})

	r := &countingResolver{err: errors.New("platform unavailable")}
	drift, warnings, err := detectDriftWithPartialFailure(context.Background(), lf,
		map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: r}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 0 {
		t.Error("a failed resolution is not drift")
	}
	if len(warnings) != 1 {
		t.Fatalf("want one warning, got %v", warnings)
	}
}

// An unknown ecosystem must be reported, not silently treated as verified.
func TestDetectDrift_UnknownEcosystemWarns(t *testing.T) {
	lf := lockfileWith(manifest.ToolEntry{
		Ecosystem: "cargo", Reference: "serde@1.0", Hash: "abc", Algorithm: "sha256",
	})

	_, warnings, err := detectDriftWithPartialFailure(context.Background(), lf,
		map[resolver.Ecosystem]resolver.Resolver{}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "cargo") {
		t.Errorf("want a warning naming the unknown ecosystem, got %v", warnings)
	}
}

// The distinction the exit codes exist to draw: an SCG outage must not look
// like a supply chain finding.
func TestExitCodeFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"no error is clean", nil, ExitClean},
		{"drift is a finding", errors.New("drift detected: 1 tool(s) changed"), ExitFinding},
		{"platform outage is operational", operational("platform unreachable"), ExitOperational},
		{"a wrapped operational error is still operational",
			errors.New("x"), ExitFinding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeFor(tt.err); got != tt.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestOperationalError_Unwraps(t *testing.T) {
	base := errors.New("connection refused")
	err := operational("cannot reach platform: %w", base)

	if !errors.Is(err, base) {
		t.Error("an operational error must unwrap to its cause")
	}
	if exitCodeFor(err) != ExitOperational {
		t.Error("an operational error must map to the operational exit code")
	}
}

func TestCollectUniqueRefs(t *testing.T) {
	a := manifest.ToolEntry{Ecosystem: "github_action", Reference: "actions/checkout@v4", Hash: "h"}
	b := manifest.ToolEntry{Ecosystem: "npm", Reference: "left-pad@1.0.0", Hash: "h"}
	lf := lockfileWith(a, b, a, a)

	refs, counts := collectUniqueRefs(lf)
	if len(refs) != 2 {
		t.Fatalf("got %d unique refs, want 2", len(refs))
	}
	if counts[uniqueRef{"github_action", "actions/checkout@v4"}] != 3 {
		t.Errorf("checkout should cover 3 entries, got %d",
			counts[uniqueRef{"github_action", "actions/checkout@v4"}])
	}
}
