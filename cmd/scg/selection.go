package main

import (
	"fmt"
	"sort"

	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/parser"
)

// selectionChange is one difference between what the project declares now
// and what the reviewed baseline recorded.
type selectionChange struct {
	// Kind is "added" or "removed".
	Kind string
	// Ecosystem and Reference are the identity, together. A reference alone
	// is not an identity: the same name can come from two ecosystems, and a
	// hash is the answer to a comparison, not the thing being compared.
	Ecosystem string
	Reference string
	// Where names the file that declares it, for an addition.
	Where string
}

func (c selectionChange) String() string {
	if c.Where != "" {
		return fmt.Sprintf("%s %s (%s) in %s", c.Kind, c.Reference, c.Ecosystem, c.Where)
	}
	return fmt.Sprintf("%s %s (%s)", c.Kind, c.Reference, c.Ecosystem)
}

// selectionKey is the canonical identity of a dependency: ecosystem and the
// reference as declared. Deduplicating by reference alone would merge two
// different dependencies that happen to share a name.
type selectionKey struct{ ecosystem, reference string }

// compareSelection reports what the project declares that the baseline does
// not record, and what the baseline records that the project no longer
// declares.
//
// This is the check the drift comparison cannot make. Drift asks whether a
// recorded entry still resolves to the same artifact; it iterates the
// baseline, so a dependency added after the baseline was written is invisible
// to it. A reviewed baseline only means something if it still describes the
// project in front of you.
func compareSelection(declared []*parser.WorkflowFile, lf *manifest.Lockfile) []selectionChange {
	current := map[selectionKey]string{}
	for _, wf := range declared {
		for _, tool := range wf.Tools {
			key := selectionKey{tool.Ecosystem, tool.Reference}
			if _, seen := current[key]; !seen {
				current[key] = wf.Path
			}
		}
	}

	recorded := map[selectionKey]struct{}{}
	for _, p := range lf.Pipelines {
		for _, s := range p.Steps {
			for _, t := range s.Tools {
				recorded[selectionKey{t.Ecosystem, t.Reference}] = struct{}{}
			}
		}
	}

	var changes []selectionChange
	for key, where := range current {
		if _, ok := recorded[key]; !ok {
			changes = append(changes, selectionChange{
				Kind: "added", Ecosystem: key.ecosystem, Reference: key.reference, Where: where,
			})
		}
	}
	for key := range recorded {
		if _, ok := current[key]; !ok {
			changes = append(changes, selectionChange{
				Kind: "removed", Ecosystem: key.ecosystem, Reference: key.reference,
			})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		if changes[i].Ecosystem != changes[j].Ecosystem {
			return changes[i].Ecosystem < changes[j].Ecosystem
		}
		return changes[i].Reference < changes[j].Reference
	})
	return changes
}

// declaredDependencies parses the project's supported files the way
// scg init does, so the comparison sees the same set init would record.
// It returns nothing at all when the project cannot be read from here,
// which the caller reports as an unchecked item rather than as removals.
func declaredDependencies(projectRoot, workflowDir string) ([]*parser.WorkflowFile, error) {
	root := resolveProjectRoot(projectRoot, workflowDir)

	paths, err := discoverWorkflows(workflowDir)
	if err != nil {
		return nil, err
	}
	var declared []*parser.WorkflowFile
	if len(paths) > 0 {
		declared, err = parseWorkflows(parser.NewWorkflowParser(), paths)
		if err != nil {
			return nil, err
		}
	}

	if projectFiles := discoverLockfiles(root); len(projectFiles) > 0 {
		extra, err := parseWithMultiParser([]parser.Parser{
			parser.NewNPMPackageParser(),
			parser.NewPNPMLockParser(),
			parser.NewPythonLockParser(),
			parser.NewPyPIRequirementsParser(),
			parser.NewDockerfileParser(),
		}, projectFiles)
		if err != nil {
			return nil, err
		}
		declared = append(declared, extra...)
	}
	return declared, nil
}
