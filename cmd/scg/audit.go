package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

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
	_, err := doAuditDetailed(ctx, logger, workflowDir, lockfilePath, resolvers)
	return err
}

// auditOutcome is what doAuditDetailed found, for --json.
type auditOutcome struct {
	Drift      []manifest.DriftResult
	Unverified []string
	Violations []auditViolation
}

func doAuditDetailed(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string, resolvers map[resolver.Ecosystem]resolver.Resolver) (auditOutcome, error) {
	var out auditOutcome
	paths, err := discoverWorkflows(workflowDir)
	if err != nil {
		return out, err
	}

	p := parser.NewWorkflowParser()
	workflows, err := parseWorkflows(p, paths)
	if err != nil {
		return out, err
	}

	uniqueTools := collectUniqueTools(workflows)
	resolved, err := resolveTools(ctx, logger, uniqueTools, resolvers)
	if err != nil {
		return out, err
	}

	// Layer 1: Drift check against existing lockfile.
	var driftResults []manifest.DriftResult
	if _, statErr := os.Stat(lockfilePath); statErr == nil {
		lf, err := manifest.ReadLockfile(lockfilePath)
		if err != nil {
			return out, fmt.Errorf("read lockfile: %w", err)
		}
		allResolvers := buildResolvers()
		var driftWarnings []string
		driftResults, driftWarnings, err = detectDriftWithPartialFailure(ctx, lf, allResolvers)
		if err != nil {
			return out, fmt.Errorf("drift detection: %w", err)
		}
		for _, w := range driftWarnings {
			printWarning(os.Stdout, "%s", w)
		}
		out.Unverified = driftWarnings
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

			compiled, err := compileForbidden(profile.ForbiddenSecrets)
			if err != nil {
				return out, operational("profile for %s: %w", baseRef, err)
			}

			for _, secret := range envSecrets {
				for i, re := range compiled {
					if re.MatchString(secret) {
						violations = append(violations, auditViolation{
							StepName: tool.StepName,
							Secret:   secret,
							Pattern:  profile.ForbiddenSecrets[i].Pattern,
							Reason:   profile.ForbiddenSecrets[i].Reason,
						})
						break
					}
				}
			}
		}
	}

	// Print report.
	printAuditReport(os.Stdout, workflows, resolved, driftResults, violations)

	out.Drift = driftResults
	out.Violations = violations
	issues := len(driftResults) + len(violations)
	if issues > 0 {
		return out, fmt.Errorf("audit found %d issue(s)", issues)
	}

	return out, nil
}

func printAuditReport(
	w *os.File,
	workflows []*parser.WorkflowFile,
	resolved map[string]*resolver.Resolution,
	driftResults []manifest.DriftResult,
	violations []auditViolation,
) {
	outf(w, "\n  %s\n\n", bold("SCG Audit Report"))

	totalSteps := 0
	for _, wf := range workflows {
		totalSteps += len(wf.Steps)
	}
	outf(w, "  Pipelines: %d\n", len(workflows))
	outf(w, "  Steps:     %d\n", totalSteps)
	outf(w, "  Tools:     %d\n\n", len(resolved))

	outf(w, "  %s\n", bold("Dependency Integrity"))
	if len(driftResults) == 0 {
		printSuccess(w, "No drift detected.")
	} else {
		for _, d := range driftResults {
			printFailure(w, "CRITICAL: %s", d.Reference)
			outf(w, "      Locked: %s\n", dim(d.LockedHash))
			outf(w, "      Live:   %s\n", dim(d.LiveHash))
		}
	}
	outln(w)

	outf(w, "  %s\n", bold("Secret Exposure"))
	if len(violations) == 0 {
		printSuccess(w, "No secret violations found.")
	} else {
		for _, v := range violations {
			printFailure(w, "Step %q: %s — %s", v.StepName, v.Secret, v.Reason)
		}
	}
	outln(w)

	issues := len(driftResults) + len(violations)
	if issues == 0 {
		outf(w, "  Result: %s\n\n", green(bold("PASS")))
	} else {
		outf(w, "  Result: %s (%d issue(s))\n\n", red(bold("FAIL")), issues)
	}
}
