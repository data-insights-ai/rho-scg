package manifest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWriteLockfile_ReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only dirs behave differently on Windows")
	}

	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	os.Mkdir(readOnlyDir, 0o555) // read + execute, no write
	defer os.Chmod(readOnlyDir, 0o755)

	path := filepath.Join(readOnlyDir, "scg.lock")
	lf := &Lockfile{Version: CurrentVersion, GeneratedAt: time.Now()}

	err := WriteLockfile(path, lf)
	if err == nil {
		t.Fatal("expected error writing to read-only directory")
	}
}

func TestReadLockfile_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks may require privileges on Windows")
	}

	tmpDir := t.TempDir()

	// Write a real lockfile.
	realPath := filepath.Join(tmpDir, "real.lock")
	lf := &Lockfile{Version: CurrentVersion, GeneratedAt: time.Now()}
	if err := WriteLockfile(realPath, lf); err != nil {
		t.Fatal(err)
	}

	// Create a symlink to it.
	linkPath := filepath.Join(tmpDir, "link.lock")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}

	// Read via symlink — should work.
	lf2, err := ReadLockfile(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if lf2.Version != CurrentVersion {
		t.Errorf("version = %d", lf2.Version)
	}
}

func TestReadLockfile_DevNull(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/null on Windows")
	}

	_, err := ReadLockfile("/dev/null")
	if err == nil {
		t.Fatal("expected error reading /dev/null (empty content)")
	}
}

func TestWriteLockfile_LongPath(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a path with 300+ characters.
	longName := strings.Repeat("a", 200)
	path := filepath.Join(tmpDir, longName, "scg.lock")

	lf := &Lockfile{Version: CurrentVersion, GeneratedAt: time.Now()}
	err := WriteLockfile(path, lf)
	// Behavior is OS-dependent. On most systems this succeeds (255 char component limit).
	// The point is: it must not panic.
	if err != nil {
		t.Logf("long path error (expected on some OS): %v", err)
	}
}

func TestWriteLockfile_ExistingFile_Overwrite(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "scg.lock")

	// Write one pipeline.
	lf1 := &Lockfile{Version: CurrentVersion, GeneratedAt: time.Now(),
		Pipelines: []PipelineEntry{{Path: "first.yml", Type: "github_actions"}}}
	if err := WriteLockfile(path, lf1); err != nil {
		t.Fatal(err)
	}

	// Overwrite with different content.
	lf2 := &Lockfile{Version: CurrentVersion, GeneratedAt: time.Now(),
		Pipelines: []PipelineEntry{{Path: "second.yml", Type: "github_actions"}}}
	if err := WriteLockfile(path, lf2); err != nil {
		t.Fatal(err)
	}

	// Read should return the second write, with no remnant of the first.
	lf3, err := ReadLockfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(lf3.Pipelines) != 1 || lf3.Pipelines[0].Path != "second.yml" {
		t.Errorf("pipelines = %+v, want only second.yml", lf3.Pipelines)
	}
}
