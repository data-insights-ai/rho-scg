package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"

	"github.com/data-insights-ai/rho-scg/internal/config"
	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/parser"
	"github.com/data-insights-ai/rho-scg/platform"
	"github.com/data-insights-ai/rho-scg/resolver"
	"github.com/data-insights-ai/rho-scg/scoper"
)

type auditViolation struct {
	StepName string
	Secret   string
	Pattern  string
	Reason   string
}

// doAudit runs a full security audit: drift detection + secret exposure analysis.
// Both layers go through the platform — no local graph.
func doAudit(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string, resolvers map[resolver.Ecosystem]resolver.Resolver) error {
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
	resolved, err := resolveTools(ctx, logger, uniqueTools, resolvers)
	if err != nil {
		return err
	}

	// Layer 1: Drift check against existing lockfile.
	var driftResults []manifest.DriftResult
	if _, statErr := os.Stat(lockfilePath); statErr == nil {
		lf, err := manifest.ReadLockfile(lockfilePath)
		if err != nil {
			return fmt.Errorf("read lockfile: %w", err)
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

	// Layer 2: Secret scoping via platform profiles.
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)
	envSecrets := scoper.ScanEnv()

	var violations []auditViolation

	seen := make(map[string]bool)
	for _, wf := range workflows {
		for _, tool := range wf.Tools {
			if seen[tool.StepName] {
				continue
			}
			seen[tool.StepName] = true

			baseRef := extractBaseRef(tool.Reference)
			profile, err := client.FetchProfile(ctx, tool.Ecosystem, baseRef)
			if err != nil {
				logger.Info("no profile for tool", "ref", baseRef, "err", err)
				continue
			}

			for _, secret := range envSecrets {
				for _, fp := range profile.ForbiddenSecrets {
					re, err := regexp.Compile(fp.Pattern)
					if err != nil {
						continue
					}
					if re.MatchString(secret) {
						violations = append(violations, auditViolation{
							StepName: tool.StepName,
							Secret:   secret,
							Pattern:  fp.Pattern,
							Reason:   fp.Reason,
						})
						break
					}
				}
			}
		}
	}

	// Print report.
	printAuditReport(os.Stdout, workflows, resolved, driftResults, violations)

	issues := len(driftResults) + len(violations)
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
	violations []auditViolation,
) {
	fmt.Fprintf(w, "\n  %s\n\n", bold("SCG Audit Report"))

	totalSteps := 0
	for _, wf := range workflows {
		totalSteps += len(wf.Steps)
	}
	fmt.Fprintf(w, "  Pipelines: %d\n", len(workflows))
	fmt.Fprintf(w, "  Steps:     %d\n", totalSteps)
	fmt.Fprintf(w, "  Tools:     %d\n\n", len(resolved))

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

	fmt.Fprintf(w, "  %s\n", bold("Secret Exposure"))
	if len(violations) == 0 {
		printSuccess(w, "No secret violations found.")
	} else {
		for _, v := range violations {
			printFailure(w, "Step %q: %s — %s", v.StepName, v.Secret, v.Reason)
		}
	}
	fmt.Fprintln(w)

	issues := len(driftResults) + len(violations)
	if issues == 0 {
		fmt.Fprintf(w, "  Result: %s\n\n", green(bold("PASS")))
	} else {
		fmt.Fprintf(w, "  Result: %s (%d issue(s))\n\n", red(bold("FAIL")), issues)
	}
}
