package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/internal/config"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/parser"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/platform"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/scoper"
)

// doScope audits a step's secret access against its tool's security profile.
// Fetches the profile from the platform, scans local env, matches forbidden patterns.
// If sanitize is true, actually removes forbidden secrets from the environment.
func doScope(ctx context.Context, logger *slog.Logger, workflowDir, stepName string, sanitize bool) error {
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

	// 2. Fetch security profile from the platform.
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)

	baseRef := extractBaseRef(stepTool.Reference)
	profile, err := client.FetchProfile(ctx, stepTool.Ecosystem, baseRef)
	if err != nil {
		return fmt.Errorf("fetch profile for %s: %w", baseRef, err)
	}

	// 3. Scan environment for secrets.
	envSecrets := scoper.ScanEnv()

	// 4. Match secrets against forbidden patterns.
	var violations []scopeViolation
	for _, secret := range envSecrets {
		for _, fp := range profile.ForbiddenSecrets {
			re, err := regexp.Compile(fp.Pattern)
			if err != nil {
				continue
			}
			if re.MatchString(secret) {
				violations = append(violations, scopeViolation{
					Secret:  secret,
					Pattern: fp.Pattern,
					Reason:  fp.Reason,
					Tool:    stepTool.Reference,
				})
				break
			}
		}
	}

	// 5. If sanitize mode, remove blocked secrets.
	if sanitize && len(violations) > 0 {
		for _, v := range violations {
			os.Unsetenv(v.Secret)
			logger.Info("unset forbidden secret", "secret", v.Secret, "reason", v.Reason)
		}
	}

	// 6. Print results.
	printScopeOutput(os.Stdout, stepName, stepTool, profile, violations, sanitize)

	if len(violations) > 0 {
		return fmt.Errorf("%d secret violation(s) found", len(violations))
	}

	return nil
}

type scopeViolation struct {
	Secret  string
	Pattern string
	Reason  string
	Tool    string
}

func printScopeOutput(w io.Writer, stepName string, tool *parser.ToolRef, profile *platform.ProfileResponse, violations []scopeViolation, sanitized bool) {
	fmt.Fprintf(w, "\n  Step: %s\n", bold(stepName))
	fmt.Fprintf(w, "  Tool: %s\n", cyan(tool.Reference))
	fmt.Fprintf(w, "  Risk: tier %d\n", profile.RiskTier)

	if len(violations) == 0 {
		printSuccess(w, "No forbidden secrets exposed")
		fmt.Fprintln(w)
		return
	}

	action := "found"
	if sanitized {
		action = "found and removed from environment"
	}
	printFailure(w, "%d secret violation(s) %s", len(violations), action)
	fmt.Fprintln(w)
	for _, v := range violations {
		label := "BLOCKED:"
		if sanitized {
			label = "REMOVED:"
		}
		fmt.Fprintf(w, "    %s %s\n", red(label), bold(v.Secret))
		fmt.Fprintf(w, "      Pattern: %s\n", dim(v.Pattern))
		fmt.Fprintf(w, "      Reason:  %s\n\n", v.Reason)
	}
}
