package parser

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// NPMPackageParser parses package-lock.json files to extract npm dependencies.
type NPMPackageParser struct{}

// NewNPMPackageParser creates a new npm lockfile parser.
func NewNPMPackageParser() *NPMPackageParser {
	return &NPMPackageParser{}
}

// Supports reports whether this parser handles the given file path.
func (p *NPMPackageParser) Supports(path string) bool {
	return filepath.Base(path) == "package-lock.json"
}

// Parse extracts npm package references from a package-lock.json file.
func (p *NPMPackageParser) Parse(path string, content []byte) (*WorkflowFile, error) {
	var lf npmLockfile
	if err := json.Unmarshal(content, &lf); err != nil {
		return nil, fmt.Errorf("parse npm lockfile %s: %w", path, err)
	}

	wf := &WorkflowFile{
		Path: path,
		Type: "npm",
	}

	var tools []ToolRef

	if len(lf.Packages) > 0 {
		tools = parseNPMV2Packages(lf.Packages)
	} else if len(lf.Dependencies) > 0 {
		tools = parseNPMV1Dependencies(lf.Dependencies)
	}

	if len(tools) == 0 {
		return wf, nil
	}

	sort.Slice(tools, func(i, j int) bool {
		return tools[i].Reference < tools[j].Reference
	})

	for i := range tools {
		tools[i].StepName = "dependencies"
		tools[i].JobName = "npm-install"
	}

	wf.Tools = tools
	wf.Steps = []StepDef{{
		Name:  "dependencies",
		Job:   "npm-install",
		Order: 0,
	}}

	return wf, nil
}

// parseNPMV2Packages extracts packages from the v2/v3 "packages" map.
func parseNPMV2Packages(packages map[string]npmPkgEntry) []ToolRef {
	var tools []ToolRef
	for key, pkg := range packages {
		if key == "" {
			continue // skip root project entry
		}
		if pkg.Version == "" {
			continue
		}

		name := extractNPMPackageName(key)
		if name == "" {
			continue
		}

		tools = append(tools, makeNPMToolRef(name, pkg.Version))
	}
	return tools
}

// parseNPMV1Dependencies extracts packages from the v1 "dependencies" map (recursive).
func parseNPMV1Dependencies(deps map[string]npmDepEntry) []ToolRef {
	seen := make(map[string]bool)
	var tools []ToolRef
	collectV1Deps(deps, seen, &tools)
	return tools
}

func collectV1Deps(deps map[string]npmDepEntry, seen map[string]bool, tools *[]ToolRef) {
	for name, dep := range deps {
		if dep.Version == "" {
			continue
		}
		ref := name + "@" + dep.Version
		if seen[ref] {
			continue
		}
		seen[ref] = true
		*tools = append(*tools, makeNPMToolRef(name, dep.Version))

		if len(dep.Dependencies) > 0 {
			collectV1Deps(dep.Dependencies, seen, tools)
		}
	}
}

// extractNPMPackageName extracts the package name from a v2/v3 key.
// Keys look like "node_modules/express" or "node_modules/@scope/pkg".
func extractNPMPackageName(key string) string {
	const prefix = "node_modules/"
	idx := strings.LastIndex(key, prefix)
	if idx < 0 {
		return ""
	}
	return key[idx+len(prefix):]
}

func makeNPMToolRef(name, version string) ToolRef {
	ref := ToolRef{
		Ecosystem: "npm",
		Reference: name + "@" + version,
		Name:      name,
		Version:   version,
	}
	// Extract owner for scoped packages (@scope/name).
	if strings.HasPrefix(name, "@") {
		if slashIdx := strings.Index(name, "/"); slashIdx >= 0 {
			ref.Owner = name[:slashIdx]
		}
	}
	return ref
}

// npmLockfile represents the structure of package-lock.json.
type npmLockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]npmPkgEntry `json:"packages"`
	Dependencies    map[string]npmDepEntry `json:"dependencies"`
}

// npmPkgEntry is a v2/v3 package entry.
type npmPkgEntry struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

// npmDepEntry is a v1 dependency entry (may contain nested dependencies).
type npmDepEntry struct {
	Version      string                 `json:"version"`
	Dev          bool                   `json:"dev"`
	Dependencies map[string]npmDepEntry `json:"dependencies"`
}
