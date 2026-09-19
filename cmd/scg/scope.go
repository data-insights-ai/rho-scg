package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/data-insights-ai/rho-scg/internal/config"
	"github.com/data-insights-ai/rho-scg/parser"
	"github.com/data-insights-ai/rho-scg/platform"
	"github.com/data-insights-ai/rho-scg/scoper"
)

// doScope audits a step's secret access against its tool's security profile.
// Fetches the profile from the platform, scans local env, matches forbidden patterns.
// If sanitize is true, actually removes forbidden secrets from the environment.
func doScope(ctx context.Context, logger *slog.Logger, workflowDir, stepName string, sanitize bool) error {
	_, err := doScopeDetailed(ctx, logger, workflowDir, stepName, sanitize)
	return err
}

// scopeOutcome is what doScopeDetailed found, for --json.
type scopeOutcome struct {
	Tool       string
	Source     string
	Violations []scopeViolation
}

func doScopeDetailed(ctx context.Context, logger *slog.Logger, workflowDir, stepName string, sanitize bool) (scopeOutcome, error) {
	var out scopeOutcome
	// 1. Discover and parse workflows to find the step and its tool.
	paths, err := discoverWorkflows(workflowDir)
	if err != nil {
		return out, err
	}

	p := parser.NewWorkflowParser()
	workflows, err := parseWorkflows(p, paths)
	if err != nil {
		return out, err
	}

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
		return out, fmt.Errorf("step %q not found or has no tool reference", stepName)
	}

	// 2. Fetch security profile from the platform.
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)

	baseRef := extractBaseRef(stepTool.Reference)
	profile, err := client.FetchProfile(ctx, stepTool.Ecosystem, baseRef)
	if err != nil {
		return out, fmt.Errorf("fetch profile for %s: %w", baseRef, err)
	}

	// 3. Scan environment for secrets.
	envSecrets := scoper.ScanEnv()

	// 4. Match secrets against forbidden patterns.
	//
	// Patterns compile once, up front, and a pattern that will not compile is
	// a hard error. Skipping it — the previous behaviour — silently permitted
	// the very secret the rule existed to block.
	compiled, err := compileForbidden(profile.ForbiddenSecrets)
	if err != nil {
		return out, operational("profile for %s: %w", stepTool.Reference, err)
	}

	var violations []scopeViolation
	for _, secret := range envSecrets {
		for i, re := range compiled {
			if re.MatchString(secret) {
				violations = append(violations, scopeViolation{
					Secret:  secret,
					Pattern: profile.ForbiddenSecrets[i].Pattern,
					Reason:  profile.ForbiddenSecrets[i].Reason,
					Tool:    stepTool.Reference,
				})
				break
			}
		}
	}

	// 5. If sanitize mode, remove blocked secrets.
	if sanitize && len(violations) > 0 {
		for _, v := range violations {
			if err := os.Unsetenv(v.Secret); err != nil {
				// Sanitisation is the point of --sanitize. If a secret cannot
				// be removed, the step must not proceed believing it was.
				return out, operational("could not unset %s: %w", v.Secret, err)
			}
			logger.Info("unset forbidden secret", "secret", v.Secret, "reason", v.Reason)
		}
	}

	// 6. Print results.
	printScopeOutput(os.Stdout, stepName, stepTool, profile, violations, sanitize)

	out = scopeOutcome{Tool: stepTool.Reference, Source: profile.Source, Violations: violations}
	if len(violations) > 0 {
		return out, fmt.Errorf("%d secret violation(s) found", len(violations))
	}

	return out, nil
}

type scopeViolation struct {
	Secret  string
	Pattern string
	Reason  string
	Tool    string
}

func printScopeOutput(w io.Writer, stepName string, tool *parser.ToolRef, profile *platform.ProfileResponse, violations []scopeViolation, sanitized bool) {
	outf(w, "\n  Step: %s\n", bold(stepName))
	outf(w, "  Tool: %s\n", cyan(tool.Reference))
	outf(w, "  Risk: tier %d\n", profile.RiskTier)

	if len(violations) == 0 {
		printSuccess(w, "No forbidden secrets exposed")
		outln(w)
		return
	}

	action := "found"
	if sanitized {
		action = "found and removed from environment"
	}
	printFailure(w, "%d secret violation(s) %s", len(violations), action)
	outln(w)
	for _, v := range violations {
		label := "BLOCKED:"
		if sanitized {
			label = "REMOVED:"
		}
		outf(w, "    %s %s\n", red(label), bold(v.Secret))
		outf(w, "      Pattern: %s\n", dim(v.Pattern))
		outf(w, "      Reason:  %s\n\n", v.Reason)
	}
}
