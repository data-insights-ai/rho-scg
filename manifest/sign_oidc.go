package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// OIDCSigner implements keyless signing using an OIDC token from the CI environment.
// It generates an ephemeral ed25519 keypair, signs the content, and embeds the
// OIDC claims (issuer, subject) in the signature for verification.
type OIDCSigner struct {
	token   string // raw OIDC JWT
	issuer  string // extracted issuer claim
	subject string // extracted subject claim
}

// NewOIDCSigner creates a keyless signer from a CI environment OIDC token.
// It detects the token from common CI environment variables:
// - ACTIONS_ID_TOKEN_REQUEST_TOKEN (GitHub Actions)
// - CI_JOB_JWT_V2 (GitLab CI)
// - OIDC_TOKEN (generic)
func NewOIDCSigner() (*OIDCSigner, error) {
	token := detectOIDCToken()
	if token == "" {
		return nil, fmt.Errorf("no OIDC token found in CI environment (set ACTIONS_ID_TOKEN_REQUEST_TOKEN, CI_JOB_JWT_V2, or OIDC_TOKEN)")
	}

	issuer, subject, err := extractJWTClaims(token)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC token: %w", err)
	}

	return &OIDCSigner{
		token:   token,
		issuer:  issuer,
		subject: subject,
	}, nil
}

// Issuer returns the OIDC issuer URL.
func (s *OIDCSigner) Issuer() string { return s.issuer }

// Sign signs data with an ephemeral ed25519 key and embeds OIDC identity.
func (s *OIDCSigner) Sign(data []byte) (*Signature, error) {
	// Generate ephemeral keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	sig := ed25519.Sign(priv, data)

	return &Signature{
		Algorithm: "oidc+ed25519",
		Value:     base64.StdEncoding.EncodeToString(sig),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Issuer:    s.issuer,
		Subject:   s.subject,
	}, nil
}

// IsOIDCAvailable reports whether an OIDC token is available in the environment.
func IsOIDCAvailable() bool {
	return detectOIDCToken() != ""
}

func detectOIDCToken() string {
	// GitHub Actions.
	if token := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); token != "" {
		return token
	}
	// GitLab CI.
	if token := os.Getenv("CI_JOB_JWT_V2"); token != "" {
		return token
	}
	// Generic.
	if token := os.Getenv("OIDC_TOKEN"); token != "" {
		return token
	}
	return ""
}

// extractJWTClaims extracts issuer and subject from a JWT without verifying the signature.
// Full JWKS-based verification happens at verify time, not sign time.
func extractJWTClaims(token string) (issuer, subject string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (part 1).
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("parse JWT claims: %w", err)
	}

	if claims.Issuer == "" {
		return "", "", fmt.Errorf("JWT missing issuer claim")
	}

	return claims.Issuer, claims.Subject, nil
}
