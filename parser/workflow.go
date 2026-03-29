package parser

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// secretRefPattern matches ${{ secrets.NAME }} expressions.
var secretRefPattern = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// WorkflowParser parses GitHub Actions workflow YAML files.
type WorkflowParser struct{}

// NewWorkflowParser creates a new GitHub Actions workflow parser.
func NewWorkflowParser() *WorkflowParser {
	return &WorkflowParser{}
}

// Supports reports whether this parser handles the given file path.
func (p *WorkflowParser) Supports(path string) bool {
	return strings.Contains(path, ".github/workflows/") &&
		(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml"))
}

// Parse extracts tool and secret references from a GitHub Actions workflow file.
func (p *WorkflowParser) Parse(path string, content []byte) (*WorkflowFile, error) {
	var wf ghWorkflow
	if err := yaml.Unmarshal(content, &wf); err != nil {
		return nil, fmt.Errorf("parse workflow %s: %w", path, err)
	}

	result := &WorkflowFile{
		Path: path,
		Type: "github_actions",
	}

	stepOrder := 0
	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = step.ID
			}
			if stepName == "" {
				stepName = fmt.Sprintf("%s-step-%d", jobName, stepOrder)
			}

			result.Steps = append(result.Steps, StepDef{
				Name:  stepName,
				Job:   jobName,
				Order: stepOrder,
			})

			// Extract tool reference from "uses" field.
			if step.Uses != "" {
				ref := parseToolRef(step.Uses, stepName, jobName)
				if ref != nil {
					result.Tools = append(result.Tools, *ref)
				}
			}

			// Extract secret references from the step's YAML representation.
			secrets := extractSecretRefs(step, stepName, jobName)
			result.Secrets = append(result.Secrets, secrets...)

			stepOrder++
		}
	}

	return result, nil
}

// parseToolRef parses a GitHub Actions "uses" value into a ToolRef.
func parseToolRef(uses, stepName, jobName string) *ToolRef {
	// Skip local actions (e.g. ./my-action)
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") {
		return nil
	}

	// Handle Docker image actions (e.g. docker://alpine:3.19).
	// NOTE: This parsing must stay consistent with resolver.parseDockerRef()
	// in resolver/docker.go. Both split on ":" for tag and "/" for registry.
	if strings.HasPrefix(uses, "docker://") {
		imageRef := uses[len("docker://"):]
		if imageRef == "" {
			return nil
		}
		name := imageRef
		version := "latest"
		if colonIdx := strings.LastIndex(imageRef, ":"); colonIdx >= 0 {
			potentialTag := imageRef[colonIdx+1:]
			if !strings.Contains(potentialTag, "/") {
				name = imageRef[:colonIdx]
				version = potentialTag
			}
		}
		owner := ""
		if slashIdx := strings.LastIndex(name, "/"); slashIdx >= 0 {
			owner = name[:slashIdx]
		}
		return &ToolRef{
			Ecosystem: "docker",
			Reference: imageRef,
			Owner:     owner,
			Name:      name,
			Version:   version,
			StepName:  stepName,
			JobName:   jobName,
		}
	}

	// Parse owner/repo@version
	atIdx := strings.LastIndex(uses, "@")
	if atIdx < 0 {
		return nil
	}

	slug := uses[:atIdx]
	version := uses[atIdx+1:]

	parts := strings.SplitN(slug, "/", 3)
	if len(parts) < 2 {
		return nil
	}

	owner := parts[0]
	name := parts[1]
	// Handle sub-path actions like "actions/cache/restore@v4"
	ref := owner + "/" + name

	return &ToolRef{
		Ecosystem: "github_action",
		Reference: ref + "@" + version,
		Owner:     owner,
		Name:      name,
		Version:   version,
		StepName:  stepName,
		JobName:   jobName,
	}
}

// extractSecretRefs finds all ${{ secrets.X }} references in a step.
func extractSecretRefs(step ghStep, stepName, jobName string) []SecretRef {
	// Marshal the step back to YAML to search through all fields.
	data, err := yaml.Marshal(step)
	if err != nil {
		return nil
	}

	matches := secretRefPattern.FindAllSubmatch(data, -1)
	seen := make(map[string]bool)
	var refs []SecretRef

	for _, match := range matches {
		name := string(match[1])
		if seen[name] {
			continue
		}
		seen[name] = true
		refs = append(refs, SecretRef{
			Name:     name,
			Source:   "secrets",
			StepName: stepName,
			JobName:  jobName,
		})
	}

	return refs
}

// ghWorkflow is a minimal representation of a GitHub Actions workflow file.
type ghWorkflow struct {
	Name string           `yaml:"name"`
	Jobs map[string]ghJob `yaml:"jobs"`
}

type ghJob struct {
	Name  string   `yaml:"name"`
	Steps []ghStep `yaml:"steps"`
}

type ghStep struct {
	ID   string         `yaml:"id"`
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	With map[string]any `yaml:"with"`
	Env  map[string]any `yaml:"env"`
	Run  string         `yaml:"run"`
}
