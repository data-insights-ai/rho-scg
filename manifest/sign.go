package manifest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Signer signs lockfile content.
type Signer interface {
	Sign(data []byte) (*Signature, error)
}

// Verifier verifies lockfile signatures.
type Verifier interface {
	Verify(data []byte, sig *Signature) error
}

// Ed25519Signer signs with a local ed25519 private key.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
}

// NewEd25519Signer creates a signer from an ed25519 private key.
func NewEd25519Signer(key ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{privateKey: key}
}

// Sign signs the data and returns a Signature.
func (s *Ed25519Signer) Sign(data []byte) (*Signature, error) {
	sig := ed25519.Sign(s.privateKey, data)

	pub := s.privateKey.Public().(ed25519.PublicKey)

	return &Signature{
		Algorithm: "ed25519",
		Value:     base64.StdEncoding.EncodeToString(sig),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// Ed25519Verifier verifies ed25519 signatures.
type Ed25519Verifier struct{}

// Verify checks an ed25519 signature against the embedded public key.
func (v *Ed25519Verifier) Verify(data []byte, sig *Signature) error {
	if sig.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported algorithm: %s", sig.Algorithm)
	}

	pubBytes, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d", len(pubBytes))
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// SignLockfile signs a lockfile's content (excluding the signature field).
func SignLockfile(lf *Lockfile, signer Signer) error {
	// Sign the lockfile content without the signature field.
	stripped := *lf
	stripped.Signature = nil

	data, err := json.Marshal(stripped)
	if err != nil {
		return fmt.Errorf("marshal lockfile for signing: %w", err)
	}

	sig, err := signer.Sign(data)
	if err != nil {
		return fmt.Errorf("sign lockfile: %w", err)
	}

	lf.Signature = sig
	return nil
}

// VerifyLockfile verifies a lockfile's signature.
func VerifyLockfile(lf *Lockfile, verifier Verifier) error {
	if lf.Signature == nil {
		return fmt.Errorf("lockfile is not signed")
	}

	stripped := *lf
	sig := stripped.Signature
	stripped.Signature = nil

	data, err := json.Marshal(stripped)
	if err != nil {
		return fmt.Errorf("marshal lockfile for verification: %w", err)
	}

	return verifier.Verify(data, sig)
}
