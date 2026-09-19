package main

import (
	"fmt"
	"io"
	"os"
)

// MaxSourceFileBytes caps how much of a scanned input file is read.
//
// Workflows, Dockerfiles and dependency lockfiles are untrusted repository
// content: anyone who can open a pull request decides what is in them. The
// lockfile reader already enforced a cap; the files the lockfile is built FROM
// did not, which left the same hole one step upstream. 16 MB is well above any
// real input — the largest npm lockfiles in public monorepos run to a few
// megabytes.
const MaxSourceFileBytes = 16 << 20

// readSourceFile reads a scanned input file, refusing anything that is not a
// regular file of plausible size.
//
// The file-type check is the important half. os.ReadFile on a FIFO blocks
// until something writes to the other end, so a single named pipe called
// ci.yml in .github/workflows made scg init and scg audit hang until the CI job
// timed out. A character device such as /dev/zero exhausts memory instead.
// Both are things a contributor can add in a pull request, and a security gate
// that hangs is a security gate somebody switches off.
//
// os.Stat follows symlinks deliberately: a workflow symlinked to a regular file
// is a legitimate repository layout, and it is the target's type that matters.
func readSourceFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("read %s: not a regular file (%s)", path, describeMode(info.Mode()))
	}
	if info.Size() > MaxSourceFileBytes {
		return nil, fmt.Errorf("read %s: file too large (%d bytes, limit %d)",
			path, info.Size(), MaxSourceFileBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Read through a limit reader as well as checking Size(): the file can grow
	// between the stat and the read, and on some filesystems Size() is a hint.
	data, err := io.ReadAll(io.LimitReader(f, MaxSourceFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > MaxSourceFileBytes {
		return nil, fmt.Errorf("read %s: file too large (limit %d bytes)", path, MaxSourceFileBytes)
	}
	return data, nil
}

// describeMode names the file type in an error a user can act on.
func describeMode(m os.FileMode) string {
	switch {
	case m&os.ModeNamedPipe != 0:
		return "named pipe"
	case m&os.ModeDevice != 0:
		return "device"
	case m&os.ModeSocket != 0:
		return "socket"
	case m.IsDir():
		return "directory"
	case m&os.ModeIrregular != 0:
		return "irregular file"
	default:
		return m.String()
	}
}

// isRegularFile reports whether path is a regular file, for use during
// discovery so a bad entry is skipped with a named warning rather than
// surfacing later from inside a parser.
func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
