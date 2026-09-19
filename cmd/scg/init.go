package main

import (
	"context"
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
// LockfileSigner obtains a signature for canonical lockfile bytes. Injecting it
// rather than reaching for the platform client inside doInit is what lets the
// tests run without a network: the alternative, a local fallback signer, is the
// very thing that produced unverifiable lockfiles in production.
type LockfileSigner interface {
	SignLockfile(ctx context.Context, lf *manifest.Lockfile) error
}

// platformSigner signs through the SCG platform.
type platformSigner struct{ client *platform.Client }

func (s *platformSigner) SignLockfile(ctx context.Context, lf *manifest.Lockfile) error {
	return signViaPlat(ctx, s.client, lf)
}

// newPlatformSigner builds the production signer from configuration.
func newPlatformSigner() *platformSigner {
	cfg := config.Load()
	return &platformSigner{client: platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)}
}

func doInit(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string, resolvers map[resolver.Ecosystem]resolver.Resolver, signer LockfileSigner) error {
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

	// Sign via the platform. There is deliberately no fallback.
	//
	// The previous local fallback generated an ephemeral keypair, signed with
	// it, and discarded the private half — producing a signature nobody could
	// ever attest to, which check then reported as "Signature verified". An
	// unverifiable lockfile is worse than an unsigned one, because it claims a
	// property it does not have. If signing fails, init fails.
	if err := signer.SignLockfile(ctx, lf); err != nil {
		return operational("cannot sign lockfile: %w\n"+
			"scg init will not write an unsigned lockfile. Check connectivity to "+
			"the SCG platform, or set SCG_API_KEY if you are rate limited", err)
	}

	if err := manifest.WriteLockfile(lockfilePath, lf); err != nil {
		return err
	}

	printInitSummary(os.Stdout, workflows, resolved, lockfilePath)
	return nil
}

// signViaPlat sends the lockfile content to the platform for signing.
//
// The bytes come from manifest.CanonicalJSON, not a local re-implementation.
// This function previously marshalled its own stripped copy, which agreed with
// the canonical form only by coincidence: the first added or reordered field
// would have made every lockfile signed here fail verification everywhere.
func signViaPlat(ctx context.Context, client *platform.Client, lf *manifest.Lockfile) error {
	data, err := manifest.CanonicalJSON(lf)
	if err != nil {
		return fmt.Errorf("marshal for signing: %w", err)
	}

	sig, err := client.Sign(ctx, data)
	if err != nil {
		return err
	}

	// Refuse a signature this build cannot anchor. Storing one would only
	// defer the failure to check, on someone else's machine.
	if sig.Algorithm != manifest.AlgorithmPlatform {
		return fmt.Errorf("platform returned unexpected signature algorithm %q, want %q",
			sig.Algorithm, manifest.AlgorithmPlatform)
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
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		full := filepath.Join(dir, name)
		// Skip anything that is not a regular file here, so a named pipe or
		// device node never reaches os.Open at all.
		if !isRegularFile(full) {
			continue
		}
		paths = append(paths, full)
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
		content, err := readSourceFile(path)
		if err != nil {
			return nil, err
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
		lower := strings.ToLower(name)
		isLockfile := name == "package-lock.json" || name == "pnpm-lock.yaml" ||
			name == "requirements.txt" ||
			(strings.HasPrefix(name, "requirements-") && strings.HasSuffix(name, ".txt")) ||
			lower == "dockerfile" ||
			strings.HasSuffix(lower, ".dockerfile") ||
			strings.HasPrefix(lower, "dockerfile.")
		if !isLockfile {
			continue
		}
		// e.IsDir() is false for a named pipe or device node, so the type has
		// to be checked explicitly: reading either one hangs or exhausts
		// memory, and a contributor chooses what lands in the repository root.
		full := filepath.Join(repoRoot, name)
		if !isRegularFile(full) {
			continue
		}
		paths = append(paths, full)
	}

	sort.Strings(paths)
	return paths
}

// parseWithMultiParser routes each file to the first parser that supports it.
func parseWithMultiParser(parsers []parser.Parser, paths []string) ([]*parser.WorkflowFile, error) {
	var results []*parser.WorkflowFile
	for _, path := range paths {
		content, err := readSourceFile(path)
		if err != nil {
			return nil, err
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
	outf(w, "\n  Resolving digests:\n")
	refs := make([]string, 0, len(resolved))
	for ref := range resolved {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		res := resolved[ref]
		printSuccess(w, "%-40s %s", ref, dim(res.Algorithm+":"+res.Hash[:minHashLen(len(res.Hash))]))
	}

	outf(w, "\n  Written: %s (%d entries, signed)\n\n", bold(lockfilePath), len(resolved))
}

func minHashLen(l int) int {
	if l < 16 {
		return l
	}
	return 16
}
