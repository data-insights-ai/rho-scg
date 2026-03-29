package manifest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// OIDCClaims holds the claims from an OIDC JWT.
type OIDCClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
}

// VerifyOIDCClaims validates the structure and temporal claims of an OIDC token.
// It checks expiration and not-before against the given timestamp (unix seconds).
//
// IMPORTANT: This does NOT verify the JWT cryptographic signature. That requires
// JWKS fetching from the issuer's well-known endpoint, which is a platform-tier
// feature. This function only validates the claim structure and temporal bounds.
//
// For production OIDC-bound signatures, the platform will:
// 1. Fetch JWKS from the issuer
// 2. Verify the JWT signature against the keyset
// 3. Validate claims (this function)
// 4. Only then trust the identity
func VerifyOIDCClaims(token string, nowUnix int64) (*OIDCClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims OIDCClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	if claims.Issuer == "" {
		return nil, fmt.Errorf("JWT missing issuer claim")
	}

	// Check expiration.
	if claims.ExpiresAt > 0 && nowUnix > claims.ExpiresAt {
		return nil, fmt.Errorf("JWT expired at %d, current time %d", claims.ExpiresAt, nowUnix)
	}

	// Check not-before.
	if claims.NotBefore > 0 && nowUnix < claims.NotBefore-30 { // 30s skew tolerance
		return nil, fmt.Errorf("JWT not valid until %d, current time %d", claims.NotBefore, nowUnix)
	}

	return &claims, nil
}
