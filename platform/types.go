package platform

import "time"

// ResolveResponse is the platform's response for a resolution request.
type ResolveResponse struct {
	Ecosystem string `json:"ecosystem"`
	Reference string `json:"reference"`
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
	Source    string `json:"source"`

	// ResolvedAt is when the platform last re-checked this reference against
	// its registry — not when the digest was first recorded. Without it the
	// CLI cannot tell a digest confirmed a minute ago from one confirmed six
	// months ago, and "no drift detected" means nothing.
	ResolvedAt time.Time `json:"resolved_at"`

	// Stale reports that the platform's own confirmation is older than the
	// freshness budget for this ecosystem. A stale answer is not a verified
	// answer, and the CLI must not report it as one.
	Stale bool `json:"stale"`

	// AgeSeconds is the age of the last confirmation.
	AgeSeconds int64 `json:"age_seconds"`

	// FreshnessBudgetSeconds is the budget Stale was computed against.
	FreshnessBudgetSeconds int64 `json:"freshness_budget_seconds"`
}

// ProfileResponse is the platform's response for a profile request.
type ProfileResponse struct {
	Tool             string          `json:"tool"`
	RiskTier         int             `json:"risk_tier"`
	RequiredSecrets  []string        `json:"required_secrets"`
	ForbiddenSecrets []ForbiddenSpec `json:"forbidden_patterns"`
}

// ForbiddenSpec describes a forbidden secret pattern.
type ForbiddenSpec struct {
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
}



// SignResponse is the platform's response for a signing request.
type SignResponse struct {
	Algorithm string `json:"algorithm"`
	// KeyID identifies which platform key produced the signature, so a key
	// rotation does not orphan previously issued signatures.
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
	PublicKey string `json:"public_key"`
}


// IntelEvent is a threat-intelligence event from /v1/intel/recent
// (a drift or burst signal detected by the platform).
type IntelEvent struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`     // "drift", "burst", ...
	Severity  string         `json:"severity"` // "critical", "high", "medium", "low"
	Ecosystem string         `json:"ecosystem"`
	Tool      string         `json:"tool"`
	Summary   string         `json:"summary"`
	Details   map[string]any `json:"details,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}
