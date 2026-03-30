package platform

import "time"

// ResolveResponse is the platform's response for a resolution request.
type ResolveResponse struct {
	Ecosystem  string    `json:"ecosystem"`
	Reference  string    `json:"reference"`
	Hash       string    `json:"hash"`
	Algorithm  string    `json:"algorithm"`
	Source     string    `json:"source"`
	ResolvedAt time.Time `json:"resolved_at"`
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

// CheckResponse is the platform's response for a batch check request.
type CheckResponse struct {
	Status string       `json:"status"` // "clean" or "drift_detected"
	Drift  []DriftEntry `json:"drift,omitempty"`
}

// DriftEntry is a single drift finding from the platform.
type DriftEntry struct {
	Ecosystem  string `json:"ecosystem"`
	Reference  string `json:"reference"`
	LockedHash string `json:"locked_hash"`
	LiveHash   string `json:"live_hash"`
	Severity   string `json:"severity"`
}

// HistoryEntry is a single entry in a tool's resolution history.
type HistoryEntry struct {
	Hash       string    `json:"hash"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidTo    time.Time `json:"valid_to,omitempty"`
}
