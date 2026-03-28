// Package parser extracts tool and secret references from CI/CD configuration files.
package parser

// ToolRef represents a tool reference found in a CI/CD config file.
type ToolRef struct {
	// Ecosystem identifies the dependency ecosystem (e.g. "github_action").
	Ecosystem string

	// Reference is the full reference string (e.g. "actions/checkout@v4").
	Reference string

	// Owner is the tool owner (e.g. "actions").
	Owner string

	// Name is the tool name (e.g. "checkout").
	Name string

	// Version is the version or tag (e.g. "v4").
	Version string

	// StepName is the name of the step using this tool.
	StepName string

	// JobName is the name of the job containing the step.
	JobName string
}

// SecretRef represents a secret reference found in a CI/CD config file.
type SecretRef struct {
	// Name is the secret name (e.g. "GITHUB_TOKEN").
	Name string

	// Source indicates where the secret comes from (e.g. "secrets", "env").
	Source string

	// StepName is the name of the step referencing this secret.
	StepName string

	// JobName is the name of the job containing the step.
	JobName string
}

// StepDef defines a step within a CI/CD job.
type StepDef struct {
	Name  string
	Job   string
	Order int
}

// WorkflowFile represents a parsed CI/CD workflow file.
type WorkflowFile struct {
	// Path is the file path relative to the repository root.
	Path string

	// Type identifies the CI/CD system (e.g. "github_actions").
	Type string

	// Tools are all tool references found in the workflow.
	Tools []ToolRef

	// Secrets are all secret references found in the workflow.
	Secrets []SecretRef

	// Steps are all step definitions across all jobs.
	Steps []StepDef
}

// Parser extracts tool and secret references from CI/CD configuration files.
type Parser interface {
	// Parse extracts references from a config file's content.
	Parse(path string, content []byte) (*WorkflowFile, error)

	// Supports reports whether this parser handles the given file path.
	Supports(path string) bool
}
