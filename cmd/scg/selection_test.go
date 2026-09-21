package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/parser"
)

// The baseline records what was reviewed. Drift iterates that record, so a
// dependency added afterwards never reaches it; this comparison is the one
// that notices, in both directions.
func TestCompareSelection(t *testing.T) {
	declared := []*parser.WorkflowFile{{
		Path: ".github/workflows/ci.yml",
		Tools: []parser.ToolRef{
			{Ecosystem: "github_action", Reference: "actions/checkout@v4"},
			{Ecosystem: "github_action", Reference: "evil/exfiltrate@v1"},
		},
	}, {
		Path:  "package-lock.json",
		Tools: []parser.ToolRef{{Ecosystem: "npm", Reference: "ms@2.1.3"}},
	}}
	lf := &manifest.Lockfile{Pipelines: []manifest.PipelineEntry{{
		Steps: []manifest.StepEntry{{
			Tools: []manifest.ToolEntry{
				{Ecosystem: "github_action", Reference: "actions/checkout@v4"},
				{Ecosystem: "github_action", Reference: "actions/setup-go@v5"},
				{Ecosystem: "npm", Reference: "ms@2.1.3"},
			},
		}},
	}}}

	changes := compareSelection(declared, lf)
	if len(changes) != 2 {
		t.Fatalf("changes = %+v, want one addition and one removal", changes)
	}
	if changes[0].Kind != "added" || changes[0].Reference != "evil/exfiltrate@v1" || changes[0].Where != ".github/workflows/ci.yml" {
		t.Errorf("addition = %+v", changes[0])
	}
	if changes[1].Kind != "removed" || changes[1].Reference != "actions/setup-go@v5" {
		t.Errorf("removal = %+v", changes[1])
	}
}

// The same reference in two ecosystems is two dependencies. Identity is the
// pair, never the reference alone.
func TestCompareSelection_EcosystemIsPartOfTheIdentity(t *testing.T) {
	declared := []*parser.WorkflowFile{{
		Path:  "requirements.txt",
		Tools: []parser.ToolRef{{Ecosystem: "pypi", Reference: "click@8.1.8"}},
	}}
	lf := &manifest.Lockfile{Pipelines: []manifest.PipelineEntry{{
		Steps: []manifest.StepEntry{{
			Tools: []manifest.ToolEntry{{Ecosystem: "npm", Reference: "click@8.1.8"}},
		}},
	}}}
	changes := compareSelection(declared, lf)
	if len(changes) != 2 {
		t.Fatalf("changes = %+v, want the pypi addition and the npm removal", changes)
	}
}

// An identical project reports nothing.
func TestCompareSelection_UnchangedProject(t *testing.T) {
	declared := []*parser.WorkflowFile{{
		Path:  "package-lock.json",
		Tools: []parser.ToolRef{{Ecosystem: "npm", Reference: "ms@2.1.3"}},
	}}
	lf := &manifest.Lockfile{Pipelines: []manifest.PipelineEntry{{
		Steps: []manifest.StepEntry{{
			Tools: []manifest.ToolEntry{{Ecosystem: "npm", Reference: "ms@2.1.3"}},
		}},
	}}}
	if changes := compareSelection(declared, lf); len(changes) != 0 {
		t.Fatalf("an unchanged project reported %+v", changes)
	}
}

// declaredDependencies reads the same inputs scg init records, so the two
// sets are comparable. A project that cannot be read from here yields
// nothing, which the caller reports as unchecked rather than as removals.
func TestDeclaredDependencies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("httpx==0.28.1\nboto3>=1.34.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	declared, err := declaredDependencies(root, filepath.Join(root, ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, wf := range declared {
		for _, tool := range wf.Tools {
			refs = append(refs, tool.Reference)
		}
	}
	if len(refs) != 1 || refs[0] != "httpx@0.28.1" {
		t.Fatalf("refs = %v, want only the pinned requirement", refs)
	}

	empty, err := declaredDependencies(t.TempDir(), filepath.Join(t.TempDir(), ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("an empty project declared %d files", len(empty))
	}
}

// A dependency added after the baseline was written is a finding, even when
// every recorded entry still verifies.
func TestDoCheck_ReportsDependencyOutsideTheBaseline(t *testing.T) {
	root := t.TempDir()
	reqs := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(reqs, []byte("httpx==0.28.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lockfilePath := filepath.Join(root, "scg.lock")
	workflows := filepath.Join(root, ".github", "workflows")
	if err := doInit(context.Background(), quietLogger(), root, workflows, lockfilePath,
		newMultiMockResolvers(), testSigner(t)); err != nil {
		t.Fatal(err)
	}

	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		t.Fatal(err)
	}
	declared, err := declaredDependencies(root, workflows)
	if err != nil {
		t.Fatal(err)
	}
	if changes := compareSelection(declared, lf); len(changes) != 0 {
		t.Fatalf("a freshly recorded project reported %+v", changes)
	}

	// Someone adds a dependency and does not re-record the baseline.
	if err := os.WriteFile(reqs, []byte("httpx==0.28.1\nclick==8.1.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	declared, err = declaredDependencies(root, workflows)
	if err != nil {
		t.Fatal(err)
	}
	changes := compareSelection(declared, lf)
	if len(changes) != 1 || changes[0].Kind != "added" || changes[0].Reference != "click@8.1.8" {
		t.Fatalf("changes = %+v, want the added dependency", changes)
	}
	if !strings.Contains(changes[0].String(), "requirements.txt") {
		t.Errorf("the finding should name the file: %s", changes[0])
	}
}
