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
	Tool             string            `json:"tool"`
	RiskTier         int               `json:"risk_tier"`
	RequiredSecrets  []SecretSpec      `json:"required_secrets"`
	ForbiddenSecrets []ForbiddenSpec   `json:"forbidden_secrets"`
	LastAudited      time.Time         `json:"last_audited"`
	AuditedBy        string            `json:"audited_by"`
}

// SecretSpec describes a secret a tool needs.
type SecretSpec struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	Required    bool     `json:"required"`
}

// ForbiddenSpec describes a forbidden secret pattern.
type ForbiddenSpec struct {
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
}

// HistoryEntry is a single entry in a tool's resolution history.
type HistoryEntry struct {
	Hash       string    `json:"hash"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidTo    time.Time `json:"valid_to,omitempty"`
}
