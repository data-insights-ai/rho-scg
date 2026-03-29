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
			return fmt.Errorf("read lockfile for drift check: %w", err)
		}
		allResolvers := buildResolvers()
		var driftWarnings []string
		driftResults, driftWarnings, err = detectDriftWithPartialFailure(ctx, lf, allResolvers)
		if err != nil {
			return fmt.Errorf("drift detection: %w", err)
		}
		for _, w := range driftWarnings {
			printWarning(os.Stdout, "%s", w)
		}
	}

	// 3. Create graph, bootstrap, populate for scope analysis.
	sg, err := scggraph.New(scggraph.Config{})
	if err != nil {
		return fmt.Errorf("create graph: %w", err)
	}
	defer sg.Close()

	if _, err := dsm.Bootstrap(ctx, sg.G); err != nil {
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
				return fmt.Errorf("scope step %q: %w", tool.StepName, err)
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
	fmt.Fprintf(w, "\n  %s\n\n", bold("SCG Audit Report"))

	totalSteps := 0
	for _, wf := range workflows {
		totalSteps += len(wf.Steps)
	}
	fmt.Fprintf(w, "  Pipelines: %d\n", len(workflows))
	fmt.Fprintf(w, "  Steps:     %d\n", totalSteps)
	fmt.Fprintf(w, "  Tools:     %d\n\n", len(resolved))

	// Drift section.
	fmt.Fprintf(w, "  %s\n", bold("Dependency Integrity"))
	if len(driftResults) == 0 {
		printSuccess(w, "No drift detected.")
	} else {
		for _, d := range driftResults {
			printFailure(w, "CRITICAL: %s", d.Reference)
			fmt.Fprintf(w, "      Locked: %s\n", dim(d.LockedHash))
			fmt.Fprintf(w, "      Live:   %s\n", dim(d.LiveHash))
		}
	}
	fmt.Fprintln(w)

	// Secret exposure section.
	fmt.Fprintf(w, "  %s\n", bold("Secret Exposure"))
	if len(scopeResults) == 0 {
		printSuccess(w, "No secret violations found.")
	} else {
		for _, sr := range scopeResults {
			printFailure(w, "Step %q: %d violation(s)", sr.StepName, len(sr.Violations))
			for _, v := range sr.Violations {
				fmt.Fprintf(w, "      %s — %s %s\n", bold(v.Secret), v.Reason, dim("("+v.Tool+")"))
			}
		}
	}
	fmt.Fprintln(w)

	issues := len(driftResults) + len(scopeResults)
	if issues == 0 {
		fmt.Fprintf(w, "  Result: %s\n\n", green(bold("PASS")))
	} else {
		fmt.Fprintf(w, "  Result: %s (%d issue(s))\n\n", red(bold("FAIL")), issues)
	}
}
