package parser

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// PythonLockParser reads the three lock files a Python project actually
// resolves to: poetry.lock, uv.lock and Pipfile.lock.
//
// This exists because requirements.txt is not a lock file. A hand-written
// one names what the author asked for, not what pip installed: four lines
// there can become two hundred packages in the environment, and every one
// of those is a package somebody can compromise. Checking only the four
// named lines is checking the wrong thing. npm has never had this problem,
// because package-lock.json is the whole resolved tree and that is what
// the npm parser reads; these three files are Python's equivalent, so
// reading them gives Python projects the same coverage.
//
// All three record exact versions, so every entry is a baseline that can
// be verified. Development and optional groups are included: a compromised
// test dependency runs in the build like any other.
type PythonLockParser struct{}

// NewPythonLockParser creates a parser for Python lock files.
func NewPythonLockParser() *PythonLockParser { return &PythonLockParser{} }

// Supports reports whether this parser handles the given file path.
func (p *PythonLockParser) Supports(path string) bool {
	switch filepath.Base(path) {
	case "poetry.lock", "uv.lock", "Pipfile.lock":
		return true
	}
	return false
}

// Parse extracts every resolved package from a Python lock file.
func (p *PythonLockParser) Parse(path string, content []byte) (*WorkflowFile, error) {
	wf := &WorkflowFile{Path: path, Type: "pypi"}

	var (
		tools []ToolRef
		err   error
	)
	switch filepath.Base(path) {
	case "poetry.lock", "uv.lock":
		tools, err = parsePythonTOMLLock(path, content, wf)
	case "Pipfile.lock":
		tools, err = parsePipfileLock(path, content, wf)
	default:
		return nil, fmt.Errorf("parse python lockfile %s: unsupported name", path)
	}
	if err != nil {
		return nil, err
	}
	if len(tools) == 0 {
		return wf, nil
	}

	sort.Slice(tools, func(i, j int) bool { return tools[i].Reference < tools[j].Reference })
	for i := range tools {
		tools[i].StepName = "dependencies"
		tools[i].JobName = "pip-install"
	}
	wf.Tools = tools
	wf.Steps = []StepDef{{Name: "dependencies", Job: "pip-install", Order: 0}}
	return wf, nil
}

// pythonTOMLLock is the shape poetry.lock and uv.lock share: an array of
// package tables, each with a name and a version. uv.lock also lists the
// project being locked, which has no registry source and is skipped.
type pythonTOMLLock struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		// Source is uv's; a registry source is a package from an index, an
		// editable or virtual one is the project itself or a path checkout.
		Source map[string]any `toml:"source"`
	} `toml:"package"`
}

func parsePythonTOMLLock(path string, content []byte, wf *WorkflowFile) ([]ToolRef, error) {
	var lock pythonTOMLLock
	if err := toml.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse python lockfile %s: %w", path, err)
	}
	seen := make(map[string]bool, len(lock.Package))
	tools := make([]ToolRef, 0, len(lock.Package))
	for _, pkg := range lock.Package {
		name := normalizePyPIName(pkg.Name)
		version := strings.TrimSpace(pkg.Version)
		switch {
		case name == "":
			continue
		case version == "":
			// uv records the workspace member itself without a version.
			// It is not a package anyone can fetch, so it is not a
			// baseline entry and not a gap worth reporting either.
			continue
		case ownProject(pkg.Source):
			// uv lists the project being locked, and a workspace lists its
			// members. They are not dependencies and reporting them as
			// gaps would be noise about your own code.
			continue
		case !fromPackageIndex(pkg.Source):
			wf.Unsupported = append(wf.Unsupported, UnsupportedRef{
				Ecosystem: "pypi", Raw: name + " " + version,
				Reason: "not from a package index: a path, editable or version-control dependency cannot be verified against PyPI",
			})
			continue
		}
		ref := name + "@" + version
		if seen[ref] {
			continue
		}
		seen[ref] = true
		tools = append(tools, ToolRef{Ecosystem: "pypi", Reference: ref, Name: name, Version: version})
	}
	return tools, nil
}

// ownProject reports whether a uv source is the locked project itself or
// a workspace member rather than a dependency.
func ownProject(source map[string]any) bool {
	for _, key := range []string{"editable", "virtual", "workspace"} {
		if _, ok := source[key]; ok {
			return true
		}
	}
	return false
}

// fromPackageIndex reports whether a uv source is a package index. poetry
// records no source table at all, and everything in a poetry.lock that has
// a version is an index package, so an absent source means yes.
func fromPackageIndex(source map[string]any) bool {
	if len(source) == 0 {
		return true
	}
	for _, key := range []string{"registry", "pypi"} {
		if _, ok := source[key]; ok {
			return true
		}
	}
	return false
}

// pipfileLock is Pipfile.lock: two maps of name to entry, one for runtime
// and one for development.
type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	// Version is written as a specifier, "==1.2.3".
	Version string `json:"version"`
	// Git, Path and File mark a dependency that is not from an index.
	Git  string `json:"git"`
	Path string `json:"path"`
	File string `json:"file"`
}

func parsePipfileLock(path string, content []byte, wf *WorkflowFile) ([]ToolRef, error) {
	var lock pipfileLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse python lockfile %s: %w", path, err)
	}
	seen := make(map[string]bool)
	var tools []ToolRef
	for _, group := range []map[string]pipfileEntry{lock.Default, lock.Develop} {
		for rawName, entry := range group {
			name := normalizePyPIName(rawName)
			if name == "" {
				continue
			}
			if entry.Git != "" || entry.Path != "" || entry.File != "" {
				wf.Unsupported = append(wf.Unsupported, UnsupportedRef{
					Ecosystem: "pypi", Raw: rawName,
					Reason: "not from a package index: a path, file or version-control dependency cannot be verified against PyPI",
				})
				continue
			}
			version := strings.TrimPrefix(strings.TrimSpace(entry.Version), "==")
			version = strings.TrimSpace(version)
			if version == "" || strings.ContainsAny(version, "<>~!*") {
				wf.Unsupported = append(wf.Unsupported, UnsupportedRef{
					Ecosystem: "pypi", Raw: rawName + " " + entry.Version,
					Reason: "no exact version: the lock file records a range, so there is no artifact to record",
				})
				continue
			}
			ref := name + "@" + version
			if seen[ref] {
				continue
			}
			seen[ref] = true
			tools = append(tools, ToolRef{Ecosystem: "pypi", Reference: ref, Name: name, Version: version})
		}
	}
	return tools, nil
}

// normalizePyPIName applies PEP 503: names differing only in case or in
// runs of . _ - are the same project, so "Jinja2" and "zope.interface"
// compare equal however a lock file spells them. Without this the same
// package recorded by two tools would look like two dependencies, and a
// drift check would compare a baseline against a name that never matches.
func normalizePyPIName(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(name))
	lastDash := false
	for _, r := range strings.ToLower(name) {
		if r == '.' || r == '_' || r == '-' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		lastDash = false
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}
