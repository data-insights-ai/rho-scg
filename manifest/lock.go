package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultLockfileName is the default lockfile name.
const DefaultLockfileName = "scg.lock"

// ReadLockfile reads and parses a lockfile from disk.
func ReadLockfile(path string) (*Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}

	var lf Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	return &lf, nil
}

// ValidateLockfilePath checks the path doesn't contain directory traversal.
func ValidateLockfilePath(path string) error {
	cleaned := filepath.Clean(path)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("lockfile path contains directory traversal: %s", path)
	}
	return nil
}

// WriteLockfile writes a lockfile to disk as formatted JSON.
func WriteLockfile(path string, lf *Lockfile) error {
	if err := ValidateLockfilePath(path); err != nil {
		return err
	}

	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal lockfile: %w", err)
	}

	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create lockfile directory: %w", err)
		}
	}

	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write lockfile: %w", err)
	}

	return nil
}
