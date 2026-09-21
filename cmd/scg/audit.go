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
	// Skipped names what the audit could not check and why. Completeness is
	// tracked apart from findings: "nothing found" and "nothing checked"
	// are different answers and must never print the same.
	Skipped []string
}

func doAuditDetailed(ctx context.Context, logger *slog.Logger, workflowDir, lockfilePath string, resolvers map[resolver.Ecosystem]resolver.Resolver) (auditOutcome, error) {
	var out auditOutcome
	paths, err := discoverWorkflows(workflowDir)
	if err != nil {
		return out, err
	}

	var workflows []*parser.WorkflowFile
	if len(paths) > 0 {
		workflows, err = parseWorkflows(parser.NewWorkflowParser(), paths)
		if err != nil {
			return out, err
		}
	} else {
		out.Skipped = append(out.Skipped, "secret scoping: no workflow files under "+workflowDir)
	}

	uniqueTools := collectUniqueTools(workflows)
	resolved, err := resolveTools(ctx, logger, uniqueTools, resolvers)
	if err != nil {
		return out, err
	}

	// Layer 1: drift against the recorded baseline. The signature is checked
	// against the pinned platform key exactly as scg check does; an audit
	// that trusted an unverified record would report on a file an attacker
	// could have written.
	var driftResults []manifest.DriftResult
	var lockedEntries int
	if _, statErr := os.Stat(lockfilePath); statErr == nil {
		lf, err := manifest.ReadLockfile(lockfilePath)
		if err != nil {
			return out, fmt.Errorf("read lockfile: %w", err)
		}
		if lf.Signature == nil {
			return out, fmt.Errorf("lockfile %s is not signed \u2014 run 'scg init' to create a signed baseline", lockfilePath)
		}
		if err := manifest.VerifyLockfile(lf, manifest.NewPlatformVerifier()); err != nil {
			return out, fmt.Errorf("signature verification failed: %w", err)
		}
		printSuccess(os.Stdout, "Signature verified (SCG platform key %s)",
			manifest.PlatformKeyFingerprint())
		lockedEntries = countLockedTools(lf)

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
		for _, w := range driftWarnings {
			out.Skipped = append(out.Skipped, "dependency integrity: "+w)
		}
	} else {
		out.Skipped = append(out.Skipped, "dependency integrity: no baseline at "+lockfilePath)
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
				// A tool without a profile is a tool whose secrets nobody
				// compared. Saying so is the difference between "clean" and
				// "not looked at".
				logger.Info("no profile for tool", "ref", baseRef, "err", err)
				out.Skipped = append(out.Skipped, "secret scoping: no profile for "+baseRef)
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

	out.Drift = driftResults
	out.Violations = violations

	// Print report.
	printAuditReport(os.Stdout, workflows, resolved, driftResults, violations, out.Skipped, lockedEntries)

	// A finding is reported before incompleteness: a confirmed drift or a
	// secret violation stays a finding even when other items were skipped.
	issues := len(driftResults) + len(violations)
	if issues > 0 {
		return out, fmt.Errorf("audit found %d issue(s)", issues)
	}
	if len(out.Skipped) > 0 {
		return out, operational("incomplete audit: %d check(s) could not be completed \u2014 this is not a clean result", len(out.Skipped))
	}
	return out, nil
}

// countLockedTools counts the entries a baseline actually carries, so the
// report can say how much was compared rather than implying everything was.
func countLockedTools(lf *manifest.Lockfile) int {
	n := 0
	for _, p := range lf.Pipelines {
		for _, s := range p.Steps {
			n += len(s.Tools)
		}
	}
	return n
}

func printAuditReport(
	w *os.File,
	workflows []*parser.WorkflowFile,
	resolved map[string]*resolver.Resolution,
	driftResults []manifest.DriftResult,
	violations []auditViolation,
	skipped []string,
	lockedEntries int,
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
	switch {
	case lockedEntries == 0:
		printWarning(w, "No signed baseline was compared.")
	case len(driftResults) == 0:
		printSuccess(w, "No drift detected in %d baseline entries.", lockedEntries)
	default:
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

	if len(skipped) > 0 {
		outf(w, "  %s\n", bold("Not checked"))
		for _, s := range skipped {
			printWarning(w, "%s", s)
		}
		outln(w)
	}

	issues := len(driftResults) + len(violations)
	switch {
	case issues > 0:
		outf(w, "  Result: %s (%d issue(s))\n\n", red(bold("FAIL")), issues)
	case len(skipped) > 0:
		// Never PASS on an audit that did not complete: a clean report the
		// reader cannot distinguish from an unchecked one is the failure
		// mode this command exists to avoid.
		outf(w, "  Result: %s (%d check(s) not completed)\n\n", bold("INCOMPLETE"), len(skipped))
	default:
		outf(w, "  Result: %s (%d baseline entries compared)\n\n", green(bold("PASS")), lockedEntries)
	}
}
