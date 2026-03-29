package manifest

import (
	"encoding/base64"
	"testing"
)

func TestVerifyOIDCClaims_Valid(t *testing.T) {
	now := int64(1711612800)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:owner/repo:ref:refs/heads/main",
		"exp": 1711616400,
		"nbf": 1711612700,
		"iat": 1711612700
	}`))
	token := makeTestJWT(payload)

	claims, err := VerifyOIDCClaims(token, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("issuer = %q", claims.Issuer)
	}
	if claims.Subject != "repo:owner/repo:ref:refs/heads/main" {
		t.Errorf("subject = %q", claims.Subject)
	}
}

func TestVerifyOIDCClaims_Expired(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"iss": "https://example.com",
		"sub": "test",
		"exp": 1000
	}`))
	token := makeTestJWT(payload)

	_, err := VerifyOIDCClaims(token, 2000)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyOIDCClaims_NotYetValid(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"iss": "https://example.com",
		"sub": "test",
		"nbf": 5000
	}`))
	token := makeTestJWT(payload)

	_, err := VerifyOIDCClaims(token, 1000)
	if err == nil {
		t.Fatal("expected error for not-yet-valid token")
	}
}

func TestVerifyOIDCClaims_MissingIssuer(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub": "test"}`))
	token := makeTestJWT(payload)

	_, err := VerifyOIDCClaims(token, 1000)
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestVerifyOIDCClaims_NoExpiration(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"iss": "https://example.com",
		"sub": "test"
	}`))
	token := makeTestJWT(payload)

	claims, err := VerifyOIDCClaims(token, 9999999)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ExpiresAt != 0 {
		t.Errorf("exp = %d, want 0", claims.ExpiresAt)
	}
}

func TestVerifyOIDCClaims_SkewTolerance(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"iss": "https://example.com",
		"sub": "test",
		"nbf": 1020
	}`))
	token := makeTestJWT(payload)

	_, err := VerifyOIDCClaims(token, 1000)
	if err != nil {
		t.Fatalf("should pass within skew tolerance: %v", err)
	}
}

func TestVerifyOIDCClaims_InvalidToken(t *testing.T) {
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
		_, err := VerifyOIDCClaims(tt.token, 1000)
		if err == nil {
			t.Errorf("%s: expected error", tt.name)
		}
	}
}

func makeTestJWT(encodedPayload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	return header + "." + encodedPayload + "." + sig
}
