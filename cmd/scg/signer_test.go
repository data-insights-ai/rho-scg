package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/data-insights-ai/rho-scg/manifest"
)

// fakePlatformSigner stands in for the platform's signing endpoint, using a
// keypair the test also pins as trusted. Tests must never reach the network,
// and the production code has no local-signing path to borrow — deliberately,
// since that path is what produced unverifiable lockfiles in the field.
type fakePlatformSigner struct{ priv ed25519.PrivateKey }

func (f *fakePlatformSigner) SignLockfile(_ context.Context, lf *manifest.Lockfile) error {
	data, err := manifest.CanonicalJSON(lf)
	if err != nil {
		return err
	}
	pub := f.priv.Public().(ed25519.PublicKey)
	lf.Signature = &manifest.Signature{
		Algorithm: manifest.AlgorithmPlatform,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, data)),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	return nil
}

// testSigner returns a signer whose key is pinned as the trusted platform key
// for the duration of the test.
func testSigner(t *testing.T) *fakePlatformSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := manifest.PlatformPublicKey
	manifest.PlatformPublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { manifest.PlatformPublicKey = original })
	return &fakePlatformSigner{priv: priv}
}
