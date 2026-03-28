package manifest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteAndReadLockfile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "scg.lock")

	lf := &Lockfile{
		Version:     CurrentVersion,
		GeneratedAt: time.Date(2026, 3, 28, 10, 0, 0, 0, time.UTC),
		Pipelines: []PipelineEntry{
			{
				Path: ".github/workflows/ci.yml",
				Type: "github_actions",
				Steps: []StepEntry{
					{
						Name:  "checkout",
						Job:   "build",
						Order: 0,
						Tools: []ToolEntry{
							{
								Ecosystem: "github_action",
								Reference: "actions/checkout@v4",
								Hash:      "abc123",
								Algorithm: "sha256",
							},
						},
					},
				},
			},
		},
	}

	// Write.
	if err := WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}

	// Verify file exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	// Read back.
	lf2, err := ReadLockfile(path)
	if err != nil {
		t.Fatal(err)
	}

	if lf2.Version != CurrentVersion {
		t.Errorf("version = %d, want %d", lf2.Version, CurrentVersion)
	}
	if len(lf2.Pipelines) != 1 {
		t.Fatalf("pipelines = %d, want 1", len(lf2.Pipelines))
	}
	if lf2.Pipelines[0].Steps[0].Tools[0].Hash != "abc123" {
		t.Errorf("hash = %q, want abc123", lf2.Pipelines[0].Steps[0].Tools[0].Hash)
	}
}

func TestReadLockfile_NotFound(t *testing.T) {
	_, err := ReadLockfile("/nonexistent/scg.lock")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestWriteLockfile_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "scg.lock")

	lf := &Lockfile{Version: CurrentVersion, GeneratedAt: time.Now()}
	if err := WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
