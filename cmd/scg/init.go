package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/data-insights-ai/rho-scg/internal/config"
	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/parser"
	"github.com/data-insights-ai/rho-scg/platform"
	"github.com/data-insights-ai/rho-scg/resolver"
)

// doInit scans workflows, resolves via the platform, builds and signs a lockfile.
// No local graph, no DSM bootstrap — the platform handles everything.
func doInit(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string, resolvers map[resolver.Ecosystem]resolver.Resolver) error {
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

	// Discover and parse lockfiles (package-lock.json, requirements.txt, Dockerfile)
	// in the repo root derived from the workflow directory.
	repoRoot := filepath.Dir(filepath.Dir(workflowDir))
	lockfilePaths := discoverLockfiles(repoRoot)
	if len(lockfilePaths) > 0 {
		logger.Info("discovered lockfiles", "count", len(lockfilePaths))
		parsers := []parser.Parser{
			parser.NewNPMPackageParser(),
			parser.NewPNPMLockParser(),
			parser.NewPyPIRequirementsParser(),
			parser.NewDockerfileParser(),
		}
		extra, err := parseWithMultiParser(parsers, lockfilePaths)
		if err != nil {
			return err
		}
		workflows = append(workflows, extra...)
	}

	uniqueTools := collectUniqueTools(workflows)
	logger.Info("found dependencies", "tools", len(uniqueTools))

	resolved, err := resolveTools(ctx, logger, uniqueTools, resolvers)
	if err != nil {
		return err
	}

	lf := buildLockfile(workflows, resolved)

	// Sign via platform (persistent key, identity-bound).
	// Falls back to local ephemeral signing if platform is unreachable (e.g., tests, offline).
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)
	if err := signViaPlat(ctx, client, lf); err != nil {
		logger.Info("platform signing unavailable, using local ephemeral key", "err", err)
		if err := signLocal(lf); err != nil {
			return fmt.Errorf("local signing: %w", err)
		}
	}

	if err := manifest.WriteLockfile(lockfilePath, lf); err != nil {
		return err
	}

	printInitSummary(os.Stdout, workflows, resolved, lockfilePath)
	return nil
}

// signLocal signs with an ephemeral ed25519 key (used when platform is unreachable).
func signLocal(lf *manifest.Lockfile) error {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return manifest.SignLockfile(lf, manifest.NewEd25519Signer(privKey))
}

// signViaPlat sends the lockfile content to the platform for signing.
func signViaPlat(ctx context.Context, client *platform.Client, lf *manifest.Lockfile) error {
	// Marshal without signature for signing.
	stripped := *lf
	stripped.Signature = nil
	data, err := json.Marshal(stripped)
	if err != nil {
		return fmt.Errorf("marshal for signing: %w", err)
	}

	sig, err := client.Sign(ctx, data)
	if err != nil {
		return err
	}

	lf.Signature = &manifest.Signature{
		Algorithm: sig.Algorithm,
		Value:     sig.Value,
		PublicKey: sig.PublicKey,
	}
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
func resolveTools(ctx context.Context, logger *slog.Logger, tools map[string]*parser.ToolRef, resolvers map[resolver.Ecosystem]resolver.Resolver) (map[string]*resolver.Resolution, error) {
	resolved := make(map[string]*resolver.Resolution, len(tools))

	refs := make([]string, 0, len(tools))
	for ref := range tools {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	for _, ref := range refs {
		tool := tools[ref]
		eco := resolver.Ecosystem(tool.Ecosystem)
		res, ok := resolvers[eco]
		if !ok {
			return nil, fmt.Errorf("no resolver for ecosystem %q (tool %s)", eco, ref)
		}
		logger.Info("resolving", "ref", ref, "ecosystem", string(eco))
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

// discoverLockfiles finds ecosystem lockfiles in the repo root directory.
// Returns a sorted list of paths. Empty slice if none found (not an error).
func discoverLockfiles(repoRoot string) []string {
	info, err := os.Stat(repoRoot)
	if err != nil || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		return nil
	}

	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case name == "package-lock.json" || name == "pnpm-lock.yaml":
			paths = append(paths, filepath.Join(repoRoot, name))
		case name == "requirements.txt" ||
			(strings.HasPrefix(name, "requirements-") && strings.HasSuffix(name, ".txt")):
			paths = append(paths, filepath.Join(repoRoot, name))
		case strings.EqualFold(name, "dockerfile") ||
			strings.HasSuffix(strings.ToLower(name), ".dockerfile") ||
			strings.HasPrefix(strings.ToLower(name), "dockerfile."):
			paths = append(paths, filepath.Join(repoRoot, name))
		}
	}

	sort.Strings(paths)
	return paths
}

// parseWithMultiParser routes each file to the first parser that supports it.
func parseWithMultiParser(parsers []parser.Parser, paths []string) ([]*parser.WorkflowFile, error) {
	var results []*parser.WorkflowFile
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var matched parser.Parser
		for _, p := range parsers {
			if p.Supports(path) {
				matched = p
				break
			}
		}
		if matched == nil {
			continue // no parser supports this file
		}

		wf, err := matched.Parse(path, content)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		results = append(results, wf)
	}
	return results, nil
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
