package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A workflow directory is untrusted repository content: anyone who can open a
// pull request can put a file there. os.ReadFile on a FIFO blocks forever, so a
// single named pipe called ci.yml made scg init hang until the CI job timed
// out — and a security gate that hangs is one a team switches off.
func TestReadSourceFile_RefusesNonRegularFile(t *testing.T) {
	if _, err := exec.LookPath("mkfifo"); err != nil {
		t.Skip("mkfifo unavailable")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "hang.yml")
	if out, err := exec.Command("mkfifo", fifo).CombinedOutput(); err != nil {
		t.Skipf("mkfifo failed: %v (%s)", err, out)
	}

	// Must return promptly rather than block on the open.
	done := make(chan error, 1)
	go func() {
		_, err := readSourceFile(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO must be refused, not read")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("error should say why it was refused, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readSourceFile blocked on a FIFO instead of refusing it")
	}
}

// Every input is untrusted, and that rule was applied to the lockfile but not
// to the files the lockfile is built from.
func TestReadSourceFile_RefusesOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.yml")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse file: cheap to create, still reports an oversized length.
	if err := f.Truncate(MaxSourceFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := readSourceFile(path); err == nil {
		t.Fatal("an oversized input file must be refused")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error should say the file is too large, got: %v", err)
	}
}

// An ordinary workflow file must still read, symlinked or not.
func TestReadSourceFile_ReadsRegularFileAndSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "ci.yml")
	const body = "name: ci\njobs: {}\n"
	if err := os.WriteFile(real, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readSourceFile(real)
	if err != nil {
		t.Fatalf("a regular file must read: %v", err)
	}
	if string(got) != body {
		t.Errorf("content = %q, want %q", got, body)
	}

	// A symlink to a regular file is a legitimate repository layout and must
	// keep working; only the non-regular target is the problem.
	link := filepath.Join(dir, "link.yml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := readSourceFile(link); err != nil {
		t.Errorf("a symlink to a regular file must read: %v", err)
	}
}

// discoverWorkflows must not hand a non-regular file to the reader at all, so
// the error names the offending file instead of surfacing from deep in a parse.
func TestDiscoverWorkflows_SkipsNonRegularFiles(t *testing.T) {
	if _, err := exec.LookPath("mkfifo"); err != nil {
		t.Skip("mkfifo unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.yml"), []byte("name: ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("mkfifo", filepath.Join(dir, "pipe.yml")).CombinedOutput(); err != nil {
		t.Skipf("mkfifo failed: %v (%s)", err, out)
	}

	paths, err := discoverWorkflows(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "pipe.yml") {
			t.Error("discovery returned a FIFO as a workflow file")
		}
	}
	if len(paths) != 1 {
		t.Errorf("discovered %v, want only real.yml", paths)
	}
}
