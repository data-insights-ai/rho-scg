package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func signedWith(t *testing.T, priv ed25519.PrivateKey, algorithm string) (*Lockfile, *Signature) {
	t.Helper()
	lf := &Lockfile{
		Version: 1,
		Pipelines: []PipelineEntry{{
			Path: ".github/workflows/ci.yml",
			Type: "github_actions",
			Steps: []StepEntry{{
				Name:  "build",
				Tools: []ToolEntry{{Ecosystem: "github_action", Reference: "actions/checkout@v4", Hash: "goodhash", Algorithm: "sha1"}},
			}},
		}},
	}
	if err := SignLockfile(lf, NewEd25519Signer(priv)); err != nil {
		t.Fatal(err)
	}
	lf.Signature.Algorithm = algorithm
	return lf, lf.Signature
}

// THE finding. The old verifier trusted the public key carried inside the very
// file it was checking, so an attacker who edits the lockfile just mints a new
// keypair, re-signs, and embeds their own key. Verification has to be against a
// key the attacker cannot choose.
func TestPlatformVerifier_RejectsAttackerKey(t *testing.T) {
	_, attackerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lf, _ := signedWith(t, attackerKey, "ed25519-platform")

	// The signature is cryptographically valid — it just is not ours.
	if err := (&Ed25519Verifier{}).Verify([]byte("ignored"), lf.Signature); err == nil {
		_ = err // the naive verifier's behaviour is asserted below instead
	}

	v := NewPlatformVerifier()
	if err := VerifyLockfile(lf, v); err == nil {
		t.Fatal("a lockfile signed with an attacker-generated key MUST NOT verify")
	} else if !strings.Contains(err.Error(), "not signed by the SCG platform") {
		t.Errorf("error should name the real problem, got: %v", err)
	}
}

// A tampered lockfile re-signed with a fresh key is the exact attack: change a
// pinned digest, mint a key, re-sign. This must fail.
func TestPlatformVerifier_RejectsTamperThenResign(t *testing.T) {
	_, attackerKey, _ := ed25519.GenerateKey(rand.Reader)
	lf, _ := signedWith(t, attackerKey, "ed25519-platform")

	lf.Pipelines[0].Steps[0].Tools[0].Hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if err := SignLockfile(lf, NewEd25519Signer(attackerKey)); err != nil {
		t.Fatal(err)
	}
	lf.Signature.Algorithm = "ed25519-platform"

	if err := VerifyLockfile(lf, NewPlatformVerifier()); err == nil {
		t.Fatal("tamper-then-resign MUST NOT verify")
	}
}

// The genuine platform key must verify.
func TestPlatformVerifier_AcceptsPinnedKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	lf, _ := signedWith(t, priv, "ed25519-platform")

	v := &PlatformVerifier{TrustedKeys: []string{base64.StdEncoding.EncodeToString(pub)}}
	if err := VerifyLockfile(lf, v); err != nil {
		t.Fatalf("a lockfile signed by the pinned key must verify: %v", err)
	}
}

// The self-signed algorithm must be refused outright, whatever key it carries.
// Accepting it would reopen the hole through the algorithm field.
func TestPlatformVerifier_RejectsSelfSignedAlgorithm(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	lf, _ := signedWith(t, priv, "ed25519")

	v := &PlatformVerifier{TrustedKeys: []string{base64.StdEncoding.EncodeToString(pub)}}
	err := VerifyLockfile(lf, v)
	if err == nil {
		t.Fatal("a locally self-signed lockfile must not verify against the platform anchor")
	}
	if !strings.Contains(err.Error(), "ed25519-platform") {
		t.Errorf("error should explain the required algorithm, got: %v", err)
	}
}

// Tampering with the payload while keeping a genuine platform signature must
// fail on the signature check itself.
func TestPlatformVerifier_RejectsTamperedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	lf, _ := signedWith(t, priv, "ed25519-platform")

	lf.Pipelines[0].Steps[0].Tools[0].Hash = "tampered"

	v := &PlatformVerifier{TrustedKeys: []string{base64.StdEncoding.EncodeToString(pub)}}
	if err := VerifyLockfile(lf, v); err == nil {
		t.Fatal("a modified payload must not verify")
	}
}

// The shipped default must be a real, well-formed ed25519 key, or every
// verification in the field fails for the wrong reason.
func TestPlatformPublicKey_IsWellFormed(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(PlatformPublicKey)
	if err != nil {
		t.Fatalf("the pinned platform key must be valid base64: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("pinned key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
}

func TestNewPlatformVerifier_UsesPinnedKey(t *testing.T) {
	v := NewPlatformVerifier()
	if len(v.TrustedKeys) == 0 {
		t.Fatal("the default verifier must carry the pinned platform key")
	}
	if v.TrustedKeys[0] != PlatformPublicKey {
		t.Errorf("TrustedKeys[0] = %q, want the pinned key", v.TrustedKeys[0])
	}
}

// The fingerprint must match the key_id the platform reports for the same key,
// or an operator comparing the two has no way to tell a mismatch from a
// formatting difference.
func TestPlatformKeyFingerprint_MatchesPlatformKeyID(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(PlatformPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:8])

	if got := PlatformKeyFingerprint(); got != want {
		t.Errorf("PlatformKeyFingerprint() = %q, want %q (platform key_id derivation)", got, want)
	}
}
