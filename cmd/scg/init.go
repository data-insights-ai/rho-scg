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

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/dsm"
	scggraph "gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/graph"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/manifest"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/parser"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
	tkgraph "gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/graph"
	"gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/types"
)

// doInit is the core orchestration for scg init.
func doInit(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string, res resolver.Resolver) error {
	// 1. Discover workflow files.
	paths, err := discoverWorkflows(workflowDir)
	if err != nil {
		return err
	}
	logger.Info("discovered workflows", "count", len(paths))

	// 2. Parse all workflows.
	p := parser.NewWorkflowParser()
	workflows, err := parseWorkflows(p, paths)
	if err != nil {
		return err
	}

	// 3. Collect unique tool references.
	uniqueTools := collectUniqueTools(workflows)
	logger.Info("found dependencies", "tools", len(uniqueTools))

	// 4. Resolve all tool references.
	resolved, err := resolveTools(ctx, logger, uniqueTools, res)
	if err != nil {
		return err
	}

	// 5. Create graph and bootstrap DSM profiles.
	sg, err := scggraph.New(scggraph.Config{})
	if err != nil {
		return fmt.Errorf("create graph: %w", err)
	}
	defer sg.Close()

	if err := dsm.Bootstrap(ctx, sg.G); err != nil {
		return fmt.Errorf("bootstrap profiles: %w", err)
	}

	// 6. Build profile map from committed DSM data.
	profileMap, err := buildProfileMap(sg.G)
	if err != nil {
		return fmt.Errorf("build profile map: %w", err)
	}

	// 7. Populate graph with pipeline data.
	if err := populateGraph(ctx, sg.G, workflows, resolved, profileMap); err != nil {
		return fmt.Errorf("populate graph: %w", err)
	}

	// 8. Create property indexes (labels now registered).
	sg.EnsureIndexes()

	// 9. Build lockfile from parsed + resolved data.
	lf := buildLockfile(workflows, resolved)

	// 10. Sign lockfile.
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	signer := manifest.NewEd25519Signer(privKey)
	if err := manifest.SignLockfile(lf, signer); err != nil {
		return fmt.Errorf("sign lockfile: %w", err)
	}

	// 11. Write lockfile.
	if err := manifest.WriteLockfile(lockfilePath, lf); err != nil {
		return err
	}

	// 12. Print summary.
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

// parseWorkflows parses all workflow files and returns the results.
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

// resolveTools resolves each unique tool reference to an immutable digest.
func resolveTools(ctx context.Context, logger *slog.Logger, tools map[string]*parser.ToolRef, res resolver.Resolver) (map[string]*resolver.Resolution, error) {
	resolved := make(map[string]*resolver.Resolution, len(tools))

	// Sort keys for deterministic resolution order.
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

// buildProfileMap queries the graph after DSM bootstrap to find
// all Tool → Profile links. Returns a map from base reference
// (e.g., "aquasecurity/trivy-action") to the Profile node.
func buildProfileMap(g *tkgraph.Graph) (map[string]*types.Node, error) {
	profiles := make(map[string]*types.Node)

	tools, err := g.NodesByLabel("Tool", tkgraph.QueryOpts{})
	if err != nil {
		return nil, err
	}

	for _, tool := range tools {
		refVal, ok := tool.GetProperty("reference")
		if !ok {
			continue
		}
		ref, ok := refVal.(string)
		if !ok {
			continue
		}

		rels, err := g.OutgoingRelationships(tool.InternalID().SnowflakeID(), scggraph.RelHasProfile)
		if err != nil {
			return nil, err
		}
		if len(rels) == 0 {
			continue
		}

		profileNode, err := g.GetNode(rels[0].EndNodeID().SnowflakeID())
		if err != nil {
			return nil, err
		}
		profiles[ref] = profileNode
	}

	return profiles, nil
}

// populateGraph creates all pipeline nodes and relationships in a single transaction.
func populateGraph(
	ctx context.Context,
	g *tkgraph.Graph,
	workflows []*parser.WorkflowFile,
	resolved map[string]*resolver.Resolution,
	profileMap map[string]*types.Node,
) error {
	tx := g.BeginTx()
	defer tx.Rollback()

	// Deduplication maps.
	toolNodes := make(map[string]*types.Node)
	digestNodes := make(map[string]*types.Node)
	secretNodes := make(map[string]*types.Node)

	for _, wf := range workflows {
		// Create Pipeline node.
		pipelineNode, err := tx.AddNode(
			[]string{scggraph.LabelPipeline},
			map[string]any{"path": wf.Path, "type": wf.Type},
		)
		if err != nil {
			return fmt.Errorf("create pipeline %s: %w", wf.Path, err)
		}

		// Index tools by step for USES linking.
		toolsByStep := make(map[string][]string) // stepName → []reference
		for _, t := range wf.Tools {
			toolsByStep[t.StepName] = append(toolsByStep[t.StepName], t.Reference)
		}

		// Index secrets by step for HAS_ACCESS linking.
		secretsByStep := make(map[string][]string) // stepName → []secretName
		for _, s := range wf.Secrets {
			secretsByStep[s.StepName] = append(secretsByStep[s.StepName], s.Name)
		}

		for _, step := range wf.Steps {
			// Create Step node.
			stepNode, err := tx.AddNode(
				[]string{scggraph.LabelStep},
				map[string]any{
					"name":     step.Name,
					"workflow": wf.Path,
					"job":      step.Job,
				},
			)
			if err != nil {
				return fmt.Errorf("create step %s: %w", step.Name, err)
			}

			// Pipeline → Step.
			if _, err := tx.AddRelationship(scggraph.RelContainsStep, pipelineNode, stepNode, map[string]any{
				"order": step.Order,
			}); err != nil {
				return fmt.Errorf("link pipeline→step %s: %w", step.Name, err)
			}

			// Create/link tools for this step.
			for _, ref := range toolsByStep[step.Name] {
				toolNode, err := getOrCreateTool(tx, toolNodes, wf, ref)
				if err != nil {
					return err
				}

				// Create/link digest.
				if res, ok := resolved[ref]; ok {
					digestNode, err := getOrCreateDigest(tx, digestNodes, res)
					if err != nil {
						return err
					}

					// RESOLVES_TO (temporal) — only if this pair hasn't been linked yet.
					pairKey := ref + "|" + res.Hash
					if _, exists := toolNodes["resolved:"+pairKey]; !exists {
						if _, err := tx.AddRelationship(scggraph.RelResolvesTo, toolNode, digestNode, map[string]any{
							"tkg_valid_from": res.ResolvedAt.UnixMilli(),
						}); err != nil {
							return fmt.Errorf("link tool→digest %s: %w", ref, err)
						}
						toolNodes["resolved:"+pairKey] = toolNode // track to avoid dups
					}
				}

				// Step → Tool (USES).
				if _, err := tx.AddRelationship(scggraph.RelUses, stepNode, toolNode, nil); err != nil {
					return fmt.Errorf("link step→tool %s: %w", ref, err)
				}

				// Link to DSM profile if available.
				baseRef := extractBaseRef(ref)
				profileKey := "profile:" + ref
				if _, linked := toolNodes[profileKey]; !linked {
					if profileNode, ok := profileMap[baseRef]; ok {
						if _, err := tx.AddRelationship(scggraph.RelHasProfile, toolNode, profileNode, nil); err != nil {
							return fmt.Errorf("link tool→profile %s: %w", ref, err)
						}
						toolNodes[profileKey] = toolNode // track to avoid dups
					}
				}
			}

			// Create/link secrets for this step.
			for _, secretName := range secretsByStep[step.Name] {
				secretNode, err := getOrCreateSecret(tx, secretNodes, secretName)
				if err != nil {
					return err
				}

				// Step → Secret (HAS_ACCESS).
				if _, err := tx.AddRelationship(scggraph.RelHasAccess, stepNode, secretNode, map[string]any{
					"source": "secrets",
				}); err != nil {
					return fmt.Errorf("link step→secret %s: %w", secretName, err)
				}
			}
		}
	}

	return tx.Commit()
}

func getOrCreateTool(tx *tkgraph.GraphTx, toolNodes map[string]*types.Node, wf *parser.WorkflowFile, ref string) (*types.Node, error) {
	if n, ok := toolNodes[ref]; ok {
		return n, nil
	}

	// Find the ToolRef for metadata.
	var toolRef *parser.ToolRef
	for i := range wf.Tools {
		if wf.Tools[i].Reference == ref {
			toolRef = &wf.Tools[i]
			break
		}
	}

	props := map[string]any{"reference": ref}
	if toolRef != nil {
		props["ecosystem"] = toolRef.Ecosystem
		props["owner"] = toolRef.Owner
		props["name"] = toolRef.Name
	}

	n, err := tx.AddNode([]string{scggraph.LabelTool}, props)
	if err != nil {
		return nil, fmt.Errorf("create tool %s: %w", ref, err)
	}
	toolNodes[ref] = n
	return n, nil
}

func getOrCreateDigest(tx *tkgraph.GraphTx, digestNodes map[string]*types.Node, res *resolver.Resolution) (*types.Node, error) {
	if n, ok := digestNodes[res.Hash]; ok {
		return n, nil
	}
	n, err := tx.AddNode([]string{scggraph.LabelDigest}, map[string]any{
		"hash":      res.Hash,
		"algorithm": res.Algorithm,
		"source":    res.Source,
	})
	if err != nil {
		return nil, fmt.Errorf("create digest %s: %w", res.Hash[:minHashLen(len(res.Hash))], err)
	}
	digestNodes[res.Hash] = n
	return n, nil
}

func getOrCreateSecret(tx *tkgraph.GraphTx, secretNodes map[string]*types.Node, name string) (*types.Node, error) {
	if n, ok := secretNodes[name]; ok {
		return n, nil
	}
	n, err := tx.AddNode([]string{scggraph.LabelSecret}, map[string]any{
		"name":     name,
		"source":   "workflow",
		"category": "ci",
	})
	if err != nil {
		return nil, fmt.Errorf("create secret %s: %w", name, err)
	}
	secretNodes[name] = n
	return n, nil
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

		// Index secrets by step.
		secretsByStep := make(map[string][]manifest.SecretEntry)
		for _, s := range wf.Secrets {
			secretsByStep[s.StepName] = append(secretsByStep[s.StepName], manifest.SecretEntry{
				Name:   s.Name,
				Source: s.Source,
			})
		}

		// Index tools by step.
		toolsByStep := make(map[string][]manifest.ToolEntry)
		for _, t := range wf.Tools {
			if res, ok := resolved[t.Reference]; ok {
				toolsByStep[t.StepName] = append(toolsByStep[t.StepName], manifest.ToolEntry{
					Ecosystem: t.Ecosystem,
					Reference: t.Reference,
					Hash:      res.Hash,
					Algorithm: res.Algorithm,
					Source:    res.Source,
				})
			}
		}

		for _, step := range wf.Steps {
			se := manifest.StepEntry{
				Name:    step.Name,
				Job:     step.Job,
				Order:   step.Order,
				Tools:   toolsByStep[step.Name],
				Secrets: secretsByStep[step.Name],
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
