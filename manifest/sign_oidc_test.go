package manifest

import (
	"encoding/base64"
	"testing"
)

func TestExtractJWTClaims(t *testing.T) {
	// Create a minimal JWT with known claims (no signature verification needed).
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://token.actions.githubusercontent.com","sub":"repo:owner/repo:ref:refs/heads/main"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	token := header + "." + payload + "." + sig

	issuer, subject, err := extractJWTClaims(token)
	if err != nil {
		t.Fatal(err)
	}

	if issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("issuer = %q", issuer)
	}
	if subject != "repo:owner/repo:ref:refs/heads/main" {
		t.Errorf("subject = %q", subject)
	}
}

func TestExtractJWTClaims_InvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"one part", "abc"},
		{"two parts", "abc.def"},
		{"bad base64", "abc.!!!.def"},
		{"bad json", "abc." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".def"},
		{"missing issuer", "abc." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".def"},
	}

	for _, tt := range tests {
		_, _, err := extractJWTClaims(tt.token)
		if err == nil {
			t.Errorf("%s: expected error", tt.name)
		}
	}
}

func TestIsOIDCAvailable_Default(t *testing.T) {
	// In test environment, no OIDC tokens should be available.
	// This is a basic sanity check — in CI it may be true.
	_ = IsOIDCAvailable() // should not panic
}

func TestOIDCSigner_Sign(t *testing.T) {
	// Create a signer with a fake token (bypass environment detection).
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://test.example.com","sub":"test-subject"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake"))
	fakeToken := header + "." + payload + "." + sig

	signer := &OIDCSigner{
		token:   fakeToken,
		issuer:  "https://test.example.com",
		subject: "test-subject",
	}

	data := []byte("test data to sign")
	result, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	if result.Algorithm != "oidc+ed25519" {
		t.Errorf("algorithm = %q, want oidc+ed25519", result.Algorithm)
	}
	if result.Issuer != "https://test.example.com" {
		t.Errorf("issuer = %q", result.Issuer)
	}
	if result.Subject != "test-subject" {
		t.Errorf("subject = %q", result.Subject)
	}
	if result.PublicKey == "" {
		t.Error("public key is empty")
	}
	if result.Value == "" {
		t.Error("signature value is empty")
	}

	// Verify the ed25519 signature still works.
	verifier := &Ed25519Verifier{}
	if err := verifier.Verify(data, result); err != nil {
		t.Fatalf("ed25519 verification failed: %v", err)
	}
}
