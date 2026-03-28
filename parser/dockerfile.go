package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// DockerfileParser parses Dockerfile FROM directives to extract image references.
type DockerfileParser struct{}

// NewDockerfileParser creates a new Dockerfile parser.
func NewDockerfileParser() *DockerfileParser {
	return &DockerfileParser{}
}

// Supports reports whether this parser handles the given file path.
func (p *DockerfileParser) Supports(path string) bool {
	base := strings.ToLower(path)
	return strings.HasSuffix(base, "dockerfile") ||
		strings.HasSuffix(base, ".dockerfile") ||
		strings.Contains(base, "dockerfile.")
}

// Parse extracts Docker image references from FROM directives.
func (p *DockerfileParser) Parse(path string, content []byte) (*WorkflowFile, error) {
	wf := &WorkflowFile{
		Path: path,
		Type: "docker",
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	order := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse FROM directives.
		if !strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			continue
		}

		ref, err := parseFromDirective(line)
		if err != nil {
			continue // skip unparseable FROM lines
		}

		// Skip scratch base.
		if ref.Reference == "scratch" {
			continue
		}

		stepName := fmt.Sprintf("stage-%d", order)

		// Check for AS alias.
		parts := strings.Fields(line)
		for i, part := range parts {
			if strings.EqualFold(part, "AS") && i+1 < len(parts) {
				stepName = parts[i+1]
				break
			}
		}

		wf.Tools = append(wf.Tools, *ref)
		wf.Steps = append(wf.Steps, StepDef{
			Name:  stepName,
			Job:   "docker-build",
			Order: order,
		})

		// Update step name on the tool ref.
		wf.Tools[len(wf.Tools)-1].StepName = stepName
		wf.Tools[len(wf.Tools)-1].JobName = "docker-build"

		order++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan dockerfile %s: %w", path, err)
	}

	return wf, nil
}

// parseFromDirective extracts the image reference from a FROM line.
// Handles: FROM image, FROM image:tag, FROM image@sha256:..., FROM image AS alias
func parseFromDirective(line string) (*ToolRef, error) {
	// Remove "FROM " prefix.
	rest := strings.TrimSpace(line[5:])

	// Split on whitespace to separate image from "AS alias".
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty FROM directive")
	}

	imageRef := fields[0]

	// Handle build args like FROM ${BASE_IMAGE}:${TAG}.
	if strings.Contains(imageRef, "${") || strings.Contains(imageRef, "$") {
		return nil, fmt.Errorf("FROM uses build args: %s", imageRef)
	}

	// Parse image reference.
	// Formats: image, image:tag, image@sha256:digest, registry/image:tag
	ref := &ToolRef{
		Ecosystem: "docker",
		Reference: imageRef,
	}

	// Extract name and version.
	if atIdx := strings.Index(imageRef, "@"); atIdx >= 0 {
		// image@sha256:digest
		ref.Name = imageRef[:atIdx]
		ref.Version = imageRef[atIdx+1:]
	} else if colonIdx := strings.LastIndex(imageRef, ":"); colonIdx >= 0 {
		// image:tag — but be careful with registry:port/image
		name := imageRef[:colonIdx]
		tag := imageRef[colonIdx+1:]
		// If the name contains a slash after the colon, it's a registry:port pattern
		if strings.Contains(tag, "/") {
			ref.Name = imageRef
			ref.Version = "latest"
		} else {
			ref.Name = name
			ref.Version = tag
		}
	} else {
		ref.Name = imageRef
		ref.Version = "latest"
	}

	// Extract owner (registry/namespace).
	if slashIdx := strings.LastIndex(ref.Name, "/"); slashIdx >= 0 {
		ref.Owner = ref.Name[:slashIdx]
	}

	return ref, nil
}
