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

	// 5. --sanitize clears the variables in this process and nowhere else.
	//
	// os.Unsetenv changes the environment of the running scg process. The
	// command that runs after scg is a separate process that inherited its
	// environment from the shell or the workflow runner, so it still sees
	// the variable. Calling this "removed" taught people to rely on an
	// isolation property this path does not have; the flag stays for
	// compatibility, says what it does, and the exit status is what
	// actually gates the next step.
	if sanitize && len(violations) > 0 {
		for _, v := range violations {
			if err := os.Unsetenv(v.Secret); err != nil {
				return out, operational("could not unset %s: %w", v.Secret, err)
			}
			logger.Info("cleared forbidden secret in this process", "secret", v.Secret, "reason", v.Reason)
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

	printFailure(w, "%d secret violation(s) found", len(violations))
	outln(w)
	for _, v := range violations {
		outf(w, "    %s %s\n", red("EXPOSED:"), bold(v.Secret))
		outf(w, "      Pattern: %s\n", dim(v.Pattern))
		outf(w, "      Reason:  %s\n\n", v.Reason)
	}
	if sanitized {
		outf(w, "    %s\n", dim("--sanitize cleared these variables inside scg only."))
		outf(w, "    %s\n\n", dim("The next command is a separate process and still sees them; stop the job on this exit status instead."))
	}
	outf(w, "    %s\n\n", dim("Restrict these credentials in the step that runs the tool; scg reports exposure, it does not isolate it."))
}
