package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/dsm"
	scggraph "gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/graph"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/manifest"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/parser"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/scoper"
)

// doAudit runs a full security audit: drift detection + secret exposure analysis.
func doAudit(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string, res resolver.Resolver) error {
	// 1. Parse and resolve (same as init).
	paths, err := discoverWorkflows(workflowDir)
	if err != nil {
		return err
	}

	p := parser.NewWorkflowParser()
	workflows, err := parseWorkflows(p, paths)
	if err != nil {
		return err
	}

	uniqueTools := collectUniqueTools(workflows)
	resolved, err := resolveTools(ctx, logger, uniqueTools, res)
	if err != nil {
		return err
	}

	// 2. Check drift against existing lockfile (if present).
	var driftResults []manifest.DriftResult
	if _, statErr := os.Stat(lockfilePath); statErr == nil {
		lf, err := manifest.ReadLockfile(lockfilePath)
		if err != nil {
			logger.Warn("could not read lockfile for drift check", "err", err)
		} else {
			resolvers := map[resolver.Ecosystem]resolver.Resolver{
				resolver.EcoGitHubAction: res,
			}
			driftResults, err = manifest.DetectDrift(ctx, lf, resolvers)
			if err != nil {
				logger.Warn("drift detection failed", "err", err)
			}
		}
	}

	// 3. Create graph, bootstrap, populate for scope analysis.
	sg, err := scggraph.New(scggraph.Config{})
	if err != nil {
		return fmt.Errorf("create graph: %w", err)
	}
	defer sg.Close()

	if err := dsm.Bootstrap(ctx, sg.G); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	profileMap, err := buildProfileMap(sg.G)
	if err != nil {
		return fmt.Errorf("build profile map: %w", err)
	}

	if err := populateGraph(ctx, sg.G, workflows, resolved, profileMap); err != nil {
		return fmt.Errorf("populate graph: %w", err)
	}

	// 4. Scope each step that has a tool.
	var scopeResults []*scoper.ScopeResult
	for _, wf := range workflows {
		for _, tool := range wf.Tools {
			result, err := scoper.Scope(ctx, sg.Engine, tool.StepName)
			if err != nil {
				logger.Warn("scope failed", "step", tool.StepName, "err", err)
				continue
			}
			if len(result.Violations) > 0 {
				scopeResults = append(scopeResults, result)
			}
		}
	}

	// 5. Print audit report.
	printAuditReport(os.Stdout, workflows, resolved, driftResults, scopeResults)

	issues := len(driftResults) + len(scopeResults)
	if issues > 0 {
		return fmt.Errorf("audit found %d issue(s)", issues)
	}

	return nil
}

func printAuditReport(
	w *os.File,
	workflows []*parser.WorkflowFile,
	resolved map[string]*resolver.Resolution,
	driftResults []manifest.DriftResult,
	scopeResults []*scoper.ScopeResult,
) {
	fmt.Fprintf(w, "\n  SCG Audit Report\n")
	fmt.Fprintf(w, "  ================\n\n")

	// Summary.
	totalSteps := 0
	for _, wf := range workflows {
		totalSteps += len(wf.Steps)
	}
	fmt.Fprintf(w, "  Pipelines: %d\n", len(workflows))
	fmt.Fprintf(w, "  Steps:     %d\n", totalSteps)
	fmt.Fprintf(w, "  Tools:     %d\n\n", len(resolved))

	// Drift section.
	fmt.Fprintf(w, "  Dependency Integrity\n")
	fmt.Fprintf(w, "  --------------------\n")
	if len(driftResults) == 0 {
		fmt.Fprintf(w, "  No drift detected.\n\n")
	} else {
		for _, d := range driftResults {
			fmt.Fprintf(w, "  CRITICAL: %s\n", d.Reference)
			fmt.Fprintf(w, "    Locked: %s\n", d.LockedHash)
			fmt.Fprintf(w, "    Live:   %s\n\n", d.LiveHash)
		}
	}

	// Secret exposure section.
	fmt.Fprintf(w, "  Secret Exposure\n")
	fmt.Fprintf(w, "  ---------------\n")
	if len(scopeResults) == 0 {
		fmt.Fprintf(w, "  No secret violations found.\n\n")
	} else {
		for _, sr := range scopeResults {
			fmt.Fprintf(w, "  Step %q: %d violation(s)\n", sr.StepName, len(sr.Violations))
			for _, v := range sr.Violations {
				fmt.Fprintf(w, "    %s — %s (%s)\n", v.Secret, v.Reason, v.Tool)
			}
			fmt.Fprintln(w)
		}
	}

	issues := len(driftResults) + len(scopeResults)
	if issues == 0 {
		fmt.Fprintf(w, "  Result: PASS\n\n")
	} else {
		fmt.Fprintf(w, "  Result: FAIL (%d issue(s))\n\n", issues)
	}
}
