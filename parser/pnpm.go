package parser

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// PNPMLockParser parses pnpm-lock.yaml files to extract npm dependencies.
//
// pnpm-lock.yaml lists every resolved package (direct and transitive) under a
// "packages:" map keyed by name@version. Registry packages carry a
// resolution.integrity; directory/link/git deps do not and are skipped (they
// can't be verified against the npm registry). Like the npm/PyPI parsers, this
// emits references without hashes — the resolver fills those in.
//
// Supported formats: pnpm v6 ('6.0'/'6.1', keys like "/lodash@4.17.21") and
// pnpm v9 ('9.0', keys like "lodash@4.17.21"). Peer-dependency suffixes in
// parentheses (e.g. "@babel/core@7.24.0(supports-color@8.1.1)") are stripped to
// the base name@version. The pnpm v5 underscore peer format is not supported.
type PNPMLockParser struct{}

// NewPNPMLockParser creates a new pnpm-lock.yaml parser.
func NewPNPMLockParser() *PNPMLockParser { return &PNPMLockParser{} }

// Supports reports whether this parser handles the given file path.
func (p *PNPMLockParser) Supports(path string) bool {
	return filepath.Base(path) == "pnpm-lock.yaml"
}

// Parse extracts npm package references from a pnpm-lock.yaml file.
func (p *PNPMLockParser) Parse(path string, content []byte) (*WorkflowFile, error) {
	var lf pnpmLockfile
	if err := yaml.Unmarshal(content, &lf); err != nil {
		return nil, fmt.Errorf("parse pnpm lockfile %s: %w", path, err)
	}

	wf := &WorkflowFile{Path: path, Type: "npm"}

	seen := make(map[string]bool)
	var tools []ToolRef
	for key, pkg := range lf.Packages {
		if pkg.Resolution.Integrity == "" {
			// A directory, link or git dependency has no registry artifact
			// to compare. Reporting it keeps "not covered" from reading as
			// "covered and clean".
			wf.Unsupported = append(wf.Unsupported, UnsupportedRef{
				Ecosystem: "npm", Raw: key,
				Reason: "not a registry dependency (directory, link or git): no integrity hash to compare",
			})
			continue
		}
		name, version, ok := splitPNPMKey(key)
		if !ok {
			wf.Unsupported = append(wf.Unsupported, UnsupportedRef{
				Ecosystem: "npm", Raw: key,
				Reason: "unsupported pnpm key format",
			})
			continue
		}
		ref := name + "@" + version
		if seen[ref] {
			continue
		}
		seen[ref] = true
		tools = append(tools, makeNPMToolRef(name, version))
	}

	if len(tools) == 0 {
		return wf, nil
	}

	sort.Slice(tools, func(i, j int) bool { return tools[i].Reference < tools[j].Reference })
	for i := range tools {
		tools[i].StepName = "dependencies"
		tools[i].JobName = "npm-install"
	}
	wf.Tools = tools
	wf.Steps = []StepDef{{Name: "dependencies", Job: "npm-install", Order: 0}}
	return wf, nil
}

// splitPNPMKey turns a pnpm package key into name and version:
//   - strips the v6 leading slash ("/lodash@4.17.21" -> "lodash@4.17.21")
//   - drops peer-dependency suffixes ("react@18(x@1)" -> "react@18")
//   - handles scoped packages ("@babel/core@7.24.0"); the version's "@" is
//     always the last one, so LastIndexByte separates name from version.
func splitPNPMKey(key string) (name, version string, ok bool) {
	key = strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i]
	}
	at := strings.LastIndexByte(key, '@')
	if at <= 0 {
		return "", "", false
	}
	name, version = key[:at], key[at+1:]
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// pnpmLockfile is the subset of pnpm-lock.yaml the parser reads.
type pnpmLockfile struct {
	Packages map[string]pnpmPkgEntry `yaml:"packages"`
}

type pnpmPkgEntry struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
	} `yaml:"resolution"`
}
