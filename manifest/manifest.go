// Package manifest defines the scg.lock data model and operations.
package manifest

import "time"

// Lockfile is the scg.lock data model.
type Lockfile struct {
	// Version is the lockfile format version.
	Version int `json:"version"`

	// GeneratedAt is when the lockfile was created or last updated.
	GeneratedAt time.Time `json:"generated_at"`

	// Pipelines contains all scanned CI/CD pipelines.
	Pipelines []PipelineEntry `json:"pipelines"`

	// Signature holds the cryptographic signature of the lockfile.
	Signature *Signature `json:"signature,omitempty"`
}

// PipelineEntry represents a single CI/CD pipeline in the lockfile.
type PipelineEntry struct {
	// Path is the pipeline file path relative to the repository root.
	Path string `json:"path"`

	// Type identifies the CI/CD system (e.g. "github_actions").
	Type string `json:"type"`

	// Repo is the repository identifier.
	Repo string `json:"repo,omitempty"`

	// Steps contains all steps with their resolved dependencies.
	Steps []StepEntry `json:"steps"`
}

// StepEntry represents a step with its resolved tool digests and secret references.
type StepEntry struct {
	// Name is the step name.
	Name string `json:"name"`

	// Job is the job containing this step.
	Job string `json:"job"`

	// Order is the step's position within its job.
	Order int `json:"order"`

	// Tools contains resolved tool references for this step.
	Tools []ToolEntry `json:"tools"`

	// Secrets contains secret references found in this step.
	Secrets []SecretEntry `json:"secrets,omitempty"`
}

// ToolEntry is a resolved tool reference with its immutable digest.
type ToolEntry struct {
	// Ecosystem identifies the dependency ecosystem.
	Ecosystem string `json:"ecosystem"`

	// Reference is the original mutable reference.
	Reference string `json:"reference"`

	// Hash is the immutable content digest.
	Hash string `json:"hash"`

	// Algorithm is the hash algorithm (e.g. "sha256").
	Algorithm string `json:"algorithm"`

	// Source identifies where the resolution was performed.
	Source string `json:"source,omitempty"`
}

// SecretEntry is a secret reference found in a step.
type SecretEntry struct {
	// Name is the secret name (e.g. "GITHUB_TOKEN").
	Name string `json:"name"`

	// Source indicates where the secret comes from.
	Source string `json:"source"`
}

// Signature holds the cryptographic signature of a lockfile.
type Signature struct {
	// Algorithm is the signing algorithm (e.g. "ed25519", "oidc+ed25519").
	Algorithm string `json:"algorithm"`

	// Value is the base64-encoded signature.
	Value string `json:"value"`

	// PublicKey is the base64-encoded public key (for keyless verification).
	PublicKey string `json:"public_key,omitempty"`

	// Issuer is the OIDC issuer URL (for keyless signing).
	Issuer string `json:"issuer,omitempty"`

	// Subject is the OIDC subject (for keyless signing).
	Subject string `json:"subject,omitempty"`
}

// CurrentVersion is the current lockfile format version.
const CurrentVersion = 1
