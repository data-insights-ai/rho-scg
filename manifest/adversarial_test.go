package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
)

// --- Lockfile edge cases ---

func TestReadLockfile_EmptyJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "scg.lock")
	os.WriteFile(path, []byte("{}"), 0o644)

	lf, err := ReadLockfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lf.Version != 0 {
		t.Errorf("version = %d, want 0 for empty JSON", lf.Version)
	}
}

func TestReadLockfile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "scg.lock")
	os.WriteFile(path, []byte("{not valid}"), 0o644)

	_, err := ReadLockfile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestReadLockfile_BinaryContent(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "scg.lock")
	binary := make([]byte, 1024)
	for i := range binary {
		binary[i] = byte(i)
	}
	os.WriteFile(path, binary, 0o644)

	_, err := ReadLockfile(path)
	if err == nil {
		t.Fatal("expected error for binary content")
	}
}

func TestReadLockfile_Truncated(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "scg.lock")
	os.WriteFile(path, []byte(`{"version": 1, "pipelines": [`), 0o644)

	_, err := ReadLockfile(path)
	if err == nil {
		t.Fatal("expected error for truncated JSON")
	}
}

func TestReadLockfile_NullValues(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "scg.lock")
	os.WriteFile(path, []byte(`{"version": 1, "generated_at": null, "pipelines": null}`), 0o644)

	lf, err := ReadLockfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lf.Version != 1 {
		t.Errorf("version = %d", lf.Version)
	}
}

// --- Signature security tests ---

func TestVerify_WrongKey(t *testing.T) {
	_, keyA, _ := ed25519.GenerateKey(rand.Reader)
	_, keyB, _ := ed25519.GenerateKey(rand.Reader)

	signerA := NewEd25519Signer(keyA)
	lf := &Lockfile{Version: 1, GeneratedAt: time.Now()}
	SignLockfile(lf, signerA)

	// Replace public key with key B — verification must fail.
	pubB := keyB.Public().(ed25519.PublicKey)
	lf.Signature.PublicKey = base64.StdEncoding.EncodeToString(pubB)

	err := VerifyLockfile(lf, &Ed25519Verifier{})
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestVerify_AlgorithmConfusion(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519Signer(key)
	lf := &Lockfile{Version: 1, GeneratedAt: time.Now()}
	SignLockfile(lf, signer)

	lf.Signature.Algorithm = "rsa"

	err := VerifyLockfile(lf, &Ed25519Verifier{})
	if err == nil {
		t.Fatal("expected error for algorithm confusion")
	}
}

func TestVerify_EmptySignature(t *testing.T) {
	lf := &Lockfile{
		Version: 1,
		Signature: &Signature{
			Algorithm: "ed25519",
			Value:     "",
			PublicKey: "",
		},
	}

	err := VerifyLockfile(lf, &Ed25519Verifier{})
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestVerify_MalformedBase64(t *testing.T) {
	lf := &Lockfile{
		Version: 1,
		Signature: &Signature{
			Algorithm: "ed25519",
			Value:     "not-valid-base64!!!",
			PublicKey: "also-not-valid!!!",
		},
	}

	err := VerifyLockfile(lf, &Ed25519Verifier{})
	if err == nil {
		t.Fatal("expected error for malformed base64")
	}
}

func TestVerify_ShortPublicKey(t *testing.T) {
	lf := &Lockfile{
		Version: 1,
		Signature: &Signature{
			Algorithm: "ed25519",
			Value:     base64.StdEncoding.EncodeToString([]byte("fake-sig")),
			PublicKey: base64.StdEncoding.EncodeToString([]byte("short")),
		},
	}

	err := VerifyLockfile(lf, &Ed25519Verifier{})
	if err == nil {
		t.Fatal("expected error for short public key")
	}
}

func TestSign_DeterministicContent(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519Signer(key)

	lf1 := &Lockfile{Version: 1, GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	lf2 := &Lockfile{Version: 1, GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	SignLockfile(lf1, signer)
	SignLockfile(lf2, signer)

	if lf1.Signature.Value != lf2.Signature.Value {
		t.Error("expected deterministic signature for same content+key")
	}
}

// --- Drift edge cases ---

func TestDetectDrift_EmptyLockfile(t *testing.T) {
	lf := &Lockfile{}
	results, err := DetectDrift(nil, lf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty lockfile, got %d", len(results))
	}
}

func TestDetectDrift_EmptyHash(t *testing.T) {
	lf := &Lockfile{
		Pipelines: []PipelineEntry{
			{Steps: []StepEntry{
				{Tools: []ToolEntry{
					{Ecosystem: "github_action", Reference: "test@v1", Hash: ""},
				}},
			}},
		},
	}

	res := &fixedResolver{hash: "abc123"}
	resolvers := map[resolver.Ecosystem]resolver.Resolver{
		resolver.EcoGitHubAction: res,
	}

	results, err := DetectDrift(nil, lf, resolvers)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 drift (empty vs non-empty), got %d", len(results))
	}
}
