package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/manifest"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/parser"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
)

// doInit scans workflows, resolves via the platform, builds and signs a lockfile.
// No local graph, no DSM bootstrap — the platform handles everything.
func doInit(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string, res resolver.Resolver) error {
	paths, err := discoverWorkflows(workflowDir)
	if err != nil {
		return err
	}
	logger.Info("discovered workflows", "count", len(paths))

	p := parser.NewWorkflowParser()
	workflows, err := parseWorkflows(p, paths)
	if err != nil {
		return err
	}

	uniqueTools := collectUniqueTools(workflows)
	logger.Info("found dependencies", "tools", len(uniqueTools))

	resolved, err := resolveTools(ctx, logger, uniqueTools, res)
	if err != nil {
		return err
	}

	lf := buildLockfile(workflows, resolved)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	signer := manifest.NewEd25519Signer(privKey)
	if err := manifest.SignLockfile(lf, signer); err != nil {
		return fmt.Errorf("sign lockfile: %w", err)
	}

	if err := manifest.WriteLockfile(lockfilePath, lf); err != nil {
		return err
	}

	printInitSummary(os.Stdout, workflows, resolved, lockfilePath)
	return nil
}

// discoverWorkflows finds all .yml/.yaml files in the given directory.
func discoverWorkflows(dir string) ([]string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("workflow directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workflow directory %q is not a directory", dir)
	}

	var paths []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read workflow directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			paths = append(paths, filepath.Join(dir, name))
		}
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("no workflow files found in %q", dir)
	}

	sort.Strings(paths)
	return paths, nil
}

// parseWorkflows parses all workflow files.
func parseWorkflows(p parser.Parser, paths []string) ([]*parser.WorkflowFile, error) {
	var workflows []*parser.WorkflowFile
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		wf, err := p.Parse(path, content)
		if err != nil {
			return nil, err
		}
		workflows = append(workflows, wf)
	}
	return workflows, nil
}

// collectUniqueTools extracts unique tool references across all workflows.
func collectUniqueTools(workflows []*parser.WorkflowFile) map[string]*parser.ToolRef {
	tools := make(map[string]*parser.ToolRef)
	for _, wf := range workflows {
		for i := range wf.Tools {
			ref := &wf.Tools[i]
			if _, exists := tools[ref.Reference]; !exists {
				tools[ref.Reference] = ref
			}
		}
	}
	return tools
}

// resolveTools resolves each unique tool reference via the platform.
func resolveTools(ctx context.Context, logger *slog.Logger, tools map[string]*parser.ToolRef, res resolver.Resolver) (map[string]*resolver.Resolution, error) {
	resolved := make(map[string]*resolver.Resolution, len(tools))

	refs := make([]string, 0, len(tools))
	for ref := range tools {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	for _, ref := range refs {
		logger.Info("resolving", "ref", ref)
		r, err := res.Resolve(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", ref, err)
		}
		logger.Info("resolved", "ref", ref, "hash", r.Hash[:minHashLen(len(r.Hash))])
		resolved[ref] = r
	}

	return resolved, nil
}

// buildLockfile constructs a Lockfile from parsed workflows and resolved digests.
func buildLockfile(workflows []*parser.WorkflowFile, resolved map[string]*resolver.Resolution) *manifest.Lockfile {
	lf := &manifest.Lockfile{
		Version:     manifest.CurrentVersion,
		GeneratedAt: time.Now().UTC(),
	}

	for _, wf := range workflows {
		pe := manifest.PipelineEntry{
			Path: wf.Path,
			Type: wf.Type,
		}

		stepKey := func(job, step string) string { return job + ":" + step }

		secretsByStep := make(map[string][]manifest.SecretEntry)
		for _, s := range wf.Secrets {
			key := stepKey(s.JobName, s.StepName)
			secretsByStep[key] = append(secretsByStep[key], manifest.SecretEntry{
				Name:   s.Name,
				Source: s.Source,
			})
		}

		toolsByStep := make(map[string][]manifest.ToolEntry)
		for _, t := range wf.Tools {
			if res, ok := resolved[t.Reference]; ok {
				key := stepKey(t.JobName, t.StepName)
				toolsByStep[key] = append(toolsByStep[key], manifest.ToolEntry{
					Ecosystem: t.Ecosystem,
					Reference: t.Reference,
					Hash:      res.Hash,
					Algorithm: res.Algorithm,
					Source:    res.Source,
				})
			}
		}

		for _, step := range wf.Steps {
			key := stepKey(step.Job, step.Name)
			se := manifest.StepEntry{
				Name:    step.Name,
				Job:     step.Job,
				Order:   step.Order,
				Tools:   toolsByStep[key],
				Secrets: secretsByStep[key],
			}
			pe.Steps = append(pe.Steps, se)
		}

		lf.Pipelines = append(lf.Pipelines, pe)
	}

	return lf
}

// extractBaseRef strips @version from a reference.
func extractBaseRef(reference string) string {
	if idx := strings.LastIndex(reference, "@"); idx >= 0 {
		return reference[:idx]
	}
	return reference
}

func printInitSummary(w io.Writer, workflows []*parser.WorkflowFile, resolved map[string]*resolver.Resolution, lockfilePath string) {
	fmt.Fprintf(w, "\n  Resolving digests:\n")
	refs := make([]string, 0, len(resolved))
	for ref := range resolved {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		res := resolved[ref]
		printSuccess(w, "%-40s %s", ref, dim(res.Algorithm+":"+res.Hash[:minHashLen(len(res.Hash))]))
	}

	fmt.Fprintf(w, "\n  Written: %s (%d entries, signed)\n\n", bold(lockfilePath), len(resolved))
}

func minHashLen(l int) int {
	if l < 16 {
		return l
	}
	return 16
}
