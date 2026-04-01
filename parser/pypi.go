package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// PyPIRequirementsParser parses requirements.txt files to extract Python dependencies.
type PyPIRequirementsParser struct{}

// NewPyPIRequirementsParser creates a new requirements.txt parser.
func NewPyPIRequirementsParser() *PyPIRequirementsParser {
	return &PyPIRequirementsParser{}
}

// Supports reports whether this parser handles the given file path.
func (p *PyPIRequirementsParser) Supports(path string) bool {
	base := filepath.Base(path)
	if base == "requirements.txt" {
		return true
	}
	return strings.HasPrefix(base, "requirements-") && strings.HasSuffix(base, ".txt")
}

// Parse extracts Python package references from a requirements.txt file.
func (p *PyPIRequirementsParser) Parse(path string, content []byte) (*WorkflowFile, error) {
	wf := &WorkflowFile{
		Path: path,
		Type: "pypi",
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var tools []ToolRef

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip pip option lines.
		if isPipOption(line) {
			continue
		}

		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip environment markers.
		if idx := strings.Index(line, " ;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx >= 0 {
			// Handle no-space markers like "pkg==1.0;python_version>="3.8"".
			candidate := strings.TrimSpace(line[:idx])
			if candidate != "" {
				line = candidate
			}
		}

		// Strip extras: requests[security] -> requests.
		if bracketIdx := strings.Index(line, "["); bracketIdx >= 0 {
			if closeIdx := strings.Index(line, "]"); closeIdx > bracketIdx {
				line = line[:bracketIdx] + line[closeIdx+1:]
			}
		}

		name, version, ok := parseVersionSpec(line)
		if !ok {
			continue
		}

		tools = append(tools, ToolRef{
			Ecosystem: "pypi",
			Reference: name + "@" + version,
			Name:      name,
			Version:   version,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan requirements %s: %w", path, err)
	}

	if len(tools) == 0 {
		return wf, nil
	}

	sort.Slice(tools, func(i, j int) bool {
		return tools[i].Reference < tools[j].Reference
	})

	for i := range tools {
		tools[i].StepName = "dependencies"
		tools[i].JobName = "pip-install"
	}

	wf.Tools = tools
	wf.Steps = []StepDef{{
		Name:  "dependencies",
		Job:   "pip-install",
		Order: 0,
	}}

	return wf, nil
}

// isPipOption returns true for lines that are pip options, not package specs.
func isPipOption(line string) bool {
	return strings.HasPrefix(line, "-r ") ||
		strings.HasPrefix(line, "-e ") ||
		strings.HasPrefix(line, "-c ") ||
		strings.HasPrefix(line, "-f ") ||
		strings.HasPrefix(line, "-i ") ||
		strings.HasPrefix(line, "--")
}

// parseVersionSpec extracts the package name and version from a version specifier line.
// Returns (name, version, true) for pinnable specs (==, >=, ~=).
// Returns ("", "", false) for bare names or unsupported operators.
func parseVersionSpec(line string) (string, string, bool) {
	// Try operators in order of specificity.
	for _, op := range []string{"==", "~=", ">="} {
		if idx := strings.Index(line, op); idx >= 0 {
			name := strings.TrimSpace(line[:idx])
			version := strings.TrimSpace(line[idx+len(op):])
			// Strip any trailing version constraints (e.g., ">=1.0,<2.0" -> "1.0").
			if commaIdx := strings.Index(version, ","); commaIdx >= 0 {
				version = strings.TrimSpace(version[:commaIdx])
			}
			if name != "" && version != "" {
				return name, version, true
			}
		}
	}
	return "", "", false
}
