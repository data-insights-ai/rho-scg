package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// PlatformPublicKey is the SCG Platform's ed25519 signing key, pinned at build
// time. It is served at https://scg.data-insights.ai/v1/pubkey, but the
// copy that matters is this one: a key fetched at verification time is a key an
// attacker who controls the network or the config can substitute.
//
// Self-hosted deployments override it at build time:
//
//	go build -ldflags "-X github.com/data-insights-ai/rho-scg/manifest.PlatformPublicKey=BASE64KEY"
//
// Deliberately NOT overridable by environment variable. The threat model is an
// attacker who can modify files in the repository — which includes the workflow
// file that sets the environment — so an env override would hand back exactly
// the control this pinning removes.
var PlatformPublicKey = "Z+U1HXD+1LrnVdYXDR/MhuYaEApwtN5+wYkn6VeosWU="

// AlgorithmPlatform is the only signature algorithm a lockfile may carry.
//
// The locally self-signed "ed25519" algorithm is refused. It was produced by an
// ephemeral keypair whose private half was discarded immediately after signing,
// so nobody — not the platform, not the user — can ever reproduce or attest to
// it. It proves the file has not been corrupted in transit and nothing else.
const AlgorithmPlatform = "ed25519-platform"

// ErrUntrustedKey reports a signature made by a key that is not the pinned
// platform key.
var ErrUntrustedKey = errors.New("lockfile is not signed by the SCG platform")

// PlatformVerifier verifies a lockfile signature against a pinned set of
// trusted public keys, rather than against the key carried inside the lockfile.
//
// This is the whole point. The previous verifier read the public key out of the
// signature block and checked the signature against it, which verifies only
// that whoever wrote the file also signed it — a property every attacker
// trivially satisfies by generating their own keypair. Anchoring to a key the
// attacker cannot choose is what makes the signature mean anything.
//
// TrustedKeys holds base64-encoded ed25519 public keys. More than one entry is
// supported so a key rotation can accept both the outgoing and incoming key
// during the overlap window.
type PlatformVerifier struct {
	TrustedKeys []string
}

// NewPlatformVerifier returns a verifier anchored to the pinned platform key.
func NewPlatformVerifier() *PlatformVerifier {
	return &PlatformVerifier{TrustedKeys: []string{PlatformPublicKey}}
}

// Verify checks that the signature was made by a trusted platform key over data.
func (v *PlatformVerifier) Verify(data []byte, sig *Signature) error {
	if sig == nil {
		return errors.New("lockfile is not signed")
	}
	if sig.Algorithm != AlgorithmPlatform {
		return fmt.Errorf(
			"lockfile signature algorithm is %q, but only %q is accepted — "+
				"re-run 'scg init' against the platform to obtain a signed lockfile",
			sig.Algorithm, AlgorithmPlatform)
	}

	if !v.trusted(sig.PublicKey) {
		return fmt.Errorf("%w: signing key %s is not a pinned platform key",
			ErrUntrustedKey, truncateKey(sig.PublicKey))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d", len(pubBytes))
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
		return errors.New("signature verification failed: lockfile content does not match its signature")
	}
	return nil
}

// trusted reports whether candidate is one of the pinned keys, comparing in
// constant time so the check leaks nothing about the expected value.
func (v *PlatformVerifier) trusted(candidate string) bool {
	ok := false
	for _, k := range v.TrustedKeys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(candidate)) == 1 {
			ok = true
		}
	}
	return ok
}

// truncateKey shortens a key for error messages. Public keys are not secret,
// but full ones make errors unreadable.
func truncateKey(k string) string {
	if len(k) <= 12 {
		return k
	}
	return k[:12] + "..."
}

// PlatformKeyFingerprint returns a short, stable identifier for the pinned
// platform key, so a user can tell at a glance which trust anchor a binary
// carries — the thing they need to check when a self-hosted build and a
// released build disagree about a lockfile.
//
// It is derived exactly as the platform derives the key_id it returns from
// /v1/sign and /v1/pubkey (first 8 bytes of the SHA-256 of the raw key), so the
// two can be compared directly instead of merely looking similar.
func PlatformKeyFingerprint() string {
	raw, err := base64.StdEncoding.DecodeString(PlatformPublicKey)
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}
