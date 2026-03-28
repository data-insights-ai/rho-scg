package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestEd25519SignAndVerify(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := NewEd25519Signer(privKey)
	data := []byte("test data to sign")

	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	if sig.Algorithm != "ed25519" {
		t.Errorf("algorithm = %q, want ed25519", sig.Algorithm)
	}
	if sig.Value == "" {
		t.Error("signature value is empty")
	}
	if sig.PublicKey == "" {
		t.Error("public key is empty")
	}

	// Verify.
	verifier := &Ed25519Verifier{}
	if err := verifier.Verify(data, sig); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestEd25519Verify_TamperedData(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := NewEd25519Signer(privKey)
	data := []byte("original data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with tampered data should fail.
	tampered := []byte("tampered data")
	verifier := &Ed25519Verifier{}
	if err := verifier.Verify(tampered, sig); err == nil {
		t.Fatal("expected verification to fail for tampered data")
	}
}

func TestSignAndVerifyLockfile(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	lf := &Lockfile{
		Version:     CurrentVersion,
		GeneratedAt: time.Now(),
		Pipelines: []PipelineEntry{
			{Path: "ci.yml", Type: "github_actions"},
		},
	}

	signer := NewEd25519Signer(privKey)
	if err := SignLockfile(lf, signer); err != nil {
		t.Fatal(err)
	}

	if lf.Signature == nil {
		t.Fatal("signature not set")
	}

	verifier := &Ed25519Verifier{}
	if err := VerifyLockfile(lf, verifier); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestVerifyLockfile_Unsigned(t *testing.T) {
	lf := &Lockfile{Version: CurrentVersion}
	verifier := &Ed25519Verifier{}
	if err := VerifyLockfile(lf, verifier); err == nil {
		t.Fatal("expected error for unsigned lockfile")
	}
}

func TestVerifyLockfile_TamperedAfterSigning(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	lf := &Lockfile{
		Version:     CurrentVersion,
		GeneratedAt: time.Now(),
		Pipelines: []PipelineEntry{
			{Path: "ci.yml", Type: "github_actions"},
		},
	}

	signer := NewEd25519Signer(privKey)
	if err := SignLockfile(lf, signer); err != nil {
		t.Fatal(err)
	}

	// Tamper the lockfile after signing.
	lf.Pipelines[0].Path = "tampered.yml"

	verifier := &Ed25519Verifier{}
	if err := VerifyLockfile(lf, verifier); err == nil {
		t.Fatal("expected verification to fail for tampered lockfile")
	}
}
