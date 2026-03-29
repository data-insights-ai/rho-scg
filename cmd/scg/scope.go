package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/dsm"
	scggraph "gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/graph"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/parser"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/scoper"
	tkgraph "gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/graph"
	"gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/types"
)

// doScope audits a step's secret access against its tool's security profile.
// If sanitize is true, actually removes forbidden secrets from the environment.
func doScope(ctx context.Context, logger *slog.Logger, workflowDir, stepName string, res resolver.Resolver, sanitize bool) error {
	// 1. Discover and parse workflows to find the step and its tool.
	paths, err := discoverWorkflows(workflowDir)
	if err != nil {
		return err
	}

	p := parser.NewWorkflowParser()
	workflows, err := parseWorkflows(p, paths)
	if err != nil {
		return err
	}

	// Find the step and its tool.
	var stepTool *parser.ToolRef
	for _, wf := range workflows {
		for _, t := range wf.Tools {
			if t.StepName == stepName {
				ref := t
				stepTool = &ref
				break
			}
		}
	}
	if stepTool == nil {
		return fmt.Errorf("step %q not found or has no tool reference", stepName)
	}

	// 2. Resolve the tool.
	resolution, err := res.Resolve(ctx, stepTool.Reference)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", stepTool.Reference, err)
	}

	// 3. Create graph, bootstrap, and populate step data.
	sg, err := scggraph.New(scggraph.Config{})
	if err != nil {
		return fmt.Errorf("create graph: %w", err)
	}
	defer sg.Close()

	profileCount, err := dsm.Bootstrap(ctx, sg.G)
	if err != nil {
		return fmt.Errorf("bootstrap profiles: %w", err)
	}

	profileMap, err := buildProfileMap(sg.G)
	if err != nil {
		return fmt.Errorf("build profile map: %w", err)
	}

	// Populate minimal graph: the step, its tool, and env secrets.
	if err := populateScopeGraph(ctx, sg.G, stepName, stepTool, resolution, profileMap); err != nil {
		return fmt.Errorf("populate scope graph: %w", err)
	}

	// Sanity check: verify profile was linked.
	baseRef := extractBaseRef(stepTool.Reference)
	if _, hasProfile := profileMap[baseRef]; !hasProfile {
		printWarning(os.Stdout, "No DSM profile for %s (%d profiles loaded) — secret scoping may be incomplete", stepTool.Reference, profileCount)
	}

	// 4. Run scoper query.
	result, err := scoper.Scope(ctx, sg.Engine, stepName)
	if err != nil {
		return fmt.Errorf("scope: %w", err)
	}

	// 5. If sanitize mode, actually remove blocked secrets from the environment.
	if sanitize && len(result.Violations) > 0 {
		for _, v := range result.Violations {
			os.Unsetenv(v.Secret)
			logger.Info("unset forbidden secret", "secret", v.Secret, "reason", v.Reason)
		}
	}

	// 6. Print results.
	printScopeResult(os.Stdout, result, stepTool, sanitize)

	if len(result.Violations) > 0 {
		return fmt.Errorf("%d secret violation(s) found", len(result.Violations))
	}

	return nil
}

// populateScopeGraph creates the minimal graph needed for scoping a single step.
func populateScopeGraph(
	ctx context.Context,
	g *tkgraph.Graph,
	stepName string,
	toolRef *parser.ToolRef,
	resolution *resolver.Resolution,
	profileMap map[string]*types.Node,
) error {
	tx := g.BeginTx()
	defer tx.Rollback()

	// Create Step node.
	stepNode, err := tx.AddNode([]string{scggraph.LabelStep}, map[string]any{
		"name": stepName,
	})
	if err != nil {
		return err
	}

	// Create Tool node.
	toolNode, err := tx.AddNode([]string{scggraph.LabelTool}, map[string]any{
		"ecosystem": toolRef.Ecosystem,
		"reference": toolRef.Reference,
		"owner":     toolRef.Owner,
		"name":      toolRef.Name,
	})
	if err != nil {
		return err
	}

	// Step → Tool (USES).
	if _, err := tx.AddRelationship(scggraph.RelUses, stepNode, toolNode, nil); err != nil {
		return err
	}

	// Create Digest and RESOLVES_TO.
	digestNode, err := tx.AddNode([]string{scggraph.LabelDigest}, map[string]any{
		"hash":      resolution.Hash,
		"algorithm": resolution.Algorithm,
		"source":    resolution.Source,
	})
	if err != nil {
		return err
	}
	if _, err := tx.AddRelationship(scggraph.RelResolvesTo, toolNode, digestNode, map[string]any{
		"tkg_valid_from": resolution.ResolvedAt.UnixMilli(),
	}); err != nil {
		return err
	}

	// Link to DSM profile.
	baseRef := extractBaseRef(toolRef.Reference)
	if profileNode, ok := profileMap[baseRef]; ok {
		if _, err := tx.AddRelationship(scggraph.RelHasProfile, toolNode, profileNode, nil); err != nil {
			return err
		}
	}

	// Scan environment for secrets and create Secret + HAS_ACCESS nodes.
	envSecrets := scoper.ScanEnv()
	for _, name := range envSecrets {
		secretNode, err := tx.AddNode([]string{scggraph.LabelSecret}, map[string]any{
			"name":   name,
			"source": "env",
		})
		if err != nil {
			return err
		}
		if _, err := tx.AddRelationship(scggraph.RelHasAccess, stepNode, secretNode, map[string]any{
			"source": "env",
		}); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func printScopeResult(w io.Writer, result *scoper.ScopeResult, tool *parser.ToolRef, sanitized bool) {
	fmt.Fprintf(w, "\n  Step: %s\n", bold(result.StepName))
	fmt.Fprintf(w, "  Tool: %s\n", cyan(tool.Reference))

	if len(result.Violations) == 0 {
		printSuccess(w, "No forbidden secrets exposed")
		fmt.Fprintln(w)
		return
	}

	action := "found"
	if sanitized {
		action = "found and removed from environment"
	}
	printFailure(w, "%d secret violation(s) %s", len(result.Violations), action)
	fmt.Fprintln(w)
	for _, v := range result.Violations {
		label := "BLOCKED:"
		if sanitized {
			label = "REMOVED:"
		}
		fmt.Fprintf(w, "    %s %s\n", red(label), bold(v.Secret))
		fmt.Fprintf(w, "      Pattern: %s\n", dim(v.Pattern))
		fmt.Fprintf(w, "      Reason:  %s\n", v.Reason)
		fmt.Fprintf(w, "      Tool:    %s\n\n", dim(v.Tool))
	}
}
