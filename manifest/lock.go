package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultLockfileName is the default lockfile name.
const DefaultLockfileName = "scg.lock"

// MaxLockfileBytes caps how much of a lockfile is read. Every input is
// untrusted, and an unbounded os.ReadFile on an attacker-supplied scg.lock is
// an out-of-memory kill. 8 MB is far above any real lockfile: the largest
// monorepo lockfiles observed run to a few hundred kilobytes.
const MaxLockfileBytes = 8 << 20

// ReadLockfile reads, validates and parses a lockfile from disk.
//
// Unknown fields are rejected rather than ignored. This matters for more than
// tidiness: signature verification re-marshals the parsed struct, so any
// content that does not map to a struct field would never reach the signature
// check at all. Refusing such files closes that channel — whatever is in the
// file is what was signed.
func ReadLockfile(path string) (*Lockfile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	if info.Size() > MaxLockfileBytes {
		return nil, fmt.Errorf("read lockfile: file too large (%d bytes, limit %d)",
			info.Size(), MaxLockfileBytes)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	if len(data) > MaxLockfileBytes {
		return nil, fmt.Errorf("read lockfile: file too large (%d bytes, limit %d)",
			len(data), MaxLockfileBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var lf Lockfile
	if err := dec.Decode(&lf); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	if err := validateLockfile(&lf); err != nil {
		return nil, fmt.Errorf("invalid lockfile: %w", err)
	}
	return &lf, nil
}

// validateLockfile rejects structurally implausible lockfiles early, before any
// of their content is acted on.
func validateLockfile(lf *Lockfile) error {
	if lf.Version != CurrentVersion {
		if lf.Version == 0 {
			return fmt.Errorf("no version field — this is not an scg lockfile")
		}
		return fmt.Errorf("unsupported version %d (this build understands %d)",
			lf.Version, CurrentVersion)
	}
	for _, p := range lf.Pipelines {
		for _, s := range p.Steps {
			for _, tool := range s.Tools {
				if tool.Reference == "" {
					return fmt.Errorf("pipeline %q has a tool entry with no reference", p.Path)
				}
				if tool.Hash == "" {
					return fmt.Errorf("tool %q has no hash", tool.Reference)
				}
			}
		}
	}
	return nil
}

// ValidateLockfilePath checks that a relative lockfile path stays inside the
// working directory.
//
// The previous check looked for ".." anywhere in the cleaned path, which
// rejected legitimate directories that merely contain dots (my..dir/scg.lock)
// while doing nothing about genuine escapes. filepath.IsLocal answers the
// actual question.
//
// An absolute path is allowed: it can only come from the operator typing
// --lockfile, which is an explicit choice about their own filesystem, not
// something an untrusted input can smuggle in.
func ValidateLockfilePath(path string) error {
	if path == "" {
		return fmt.Errorf("lockfile path is empty")
	}
	if filepath.IsAbs(path) {
		return nil
	}
	if !filepath.IsLocal(filepath.Clean(path)) {
		return fmt.Errorf("lockfile path escapes the working directory: %s", path)
	}
	return nil
}

// WriteLockfile writes a lockfile to disk atomically.
//
// The write goes to a temporary file in the destination directory and is then
// renamed into place, so an interrupted or failed write can never leave a
// truncated scg.lock behind. A half-written security artifact is worse than no
// artifact: it reads as a corrupt repository rather than a failed command.
func WriteLockfile(path string, lf *Lockfile) error {
	if err := ValidateLockfilePath(path); err != nil {
		return err
	}

	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal lockfile: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create lockfile directory: %w", err)
		}
	}

	// The temporary file must live in the destination directory: rename is only
	// atomic within a filesystem, and /tmp is routinely a different one.
	tmp, err := os.CreateTemp(dir, ".scg.lock.*")
	if err != nil {
		return fmt.Errorf("create temporary lockfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup: both are no-ops once the rename has succeeded,
		// and on the failure path the error that matters is already being
		// returned below.
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write lockfile: %w", err)
	}
	// fsync before rename: without it a crash can leave the renamed file
	// present but empty on several filesystems.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync lockfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close lockfile: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("set lockfile permissions: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install lockfile: %w", err)
	}
	return nil
}
