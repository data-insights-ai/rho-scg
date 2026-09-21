// Command scg is the Supply Chain Guardian CLI.
//
// SCG prevents supply chain attacks by enforcing dependency integrity
// and secret least-privilege across CI/CD pipelines.
//
// All resolution goes through the SCG Platform (api.scg.data-insights.ai).
// No GitHub token, Docker Hub account, or registry credentials needed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/data-insights-ai/rho-scg/platform"
)

var version = "dev"

func main() {
	// The platform client identifies the build in its User-Agent; without
	// this every released binary would call itself scg/dev.
	platform.Version = version
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(ctx, os.Args[2:])
	case "check":
		err = runCheck(ctx, os.Args[2:])
	case "update":
		err = runUpdate(ctx, os.Args[2:])
	case "scope":
		err = runScope(ctx, os.Args[2:])
	case "audit":
		err = runAudit(ctx, os.Args[2:])
	case "intel":
		err = runIntel(ctx, os.Args[2:])
	case "watch":
		err = runWatch(ctx, os.Args[2:])
	case "unwatch":
		err = runUnwatch(ctx, os.Args[2:])
	case "watches":
		err = runWatches(ctx, os.Args[2:])
	case "login":
		err = runLogin(ctx, os.Args[2:])
	case "logout":
		err = runLogout(os.Args[2:])
	case "version":
		fmt.Printf("scg %s\n", version)
		return
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "scg: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		var reported *reportedError
		if errors.As(err, &reported) {
			// --json already wrote the result, exit code included.
			os.Exit(reported.code)
		}
		code := exitCodeFor(err)
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		if code == ExitOperational {
			// Say plainly that this is not a finding. A red pipeline that looks
			// like a detection, but is really an SCG outage, costs a team an
			// incident response for nothing.
			fmt.Fprintln(os.Stderr,
				"\nThis is an SCG operational failure, not a supply chain finding. "+
					"Nothing was detected about your dependencies. Retry, or check "+
					"https://api.scg.data-insights.ai/v1/status")
		}
		os.Exit(code)
	}
}

// makeLogger creates a logger based on the verbose flag.
func makeLogger(verbose bool) *slog.Logger {
	level := slog.LevelError
	if verbose {
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func runInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	rootFlag := fs.String("root", "", "project root to scan (default: the repository root of -workflows, else the working directory)")
	lockfile := fs.String("lockfile", "scg.lock", "output lockfile path")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	timeout := fs.String("timeout", "", "overall time limit, e.g. 90s or 5m (0 disables)")
	verbose := fs.Bool("verbose", false, "show detailed resolution progress")
	watch := fs.Bool("watch", false, "after writing, upload the lockfile so the platform watches its tools (needs a key)")
	repoFlag := fs.String("repo", "", "repository name for --watch (default: detected)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	limit, err := parseTimeout(*timeout)
	if err != nil {
		return err
	}
	ctx, cancel := withCommandDeadline(ctx, limit)
	defer cancel()

	logger := makeLogger(*verbose)
	resolvers := buildResolvers()

	run := func() {
		err = classifyDeadline(ctx, doInit(ctx, logger, *rootFlag, *workflowDir, *lockfile, resolvers, newPlatformSigner()), limit)
		if err == nil && *watch {
			err = watchAfterWrite(ctx, *lockfile, *repoFlag)
		}
	}
	if *jsonOut {
		humanToStderr(run)
	} else {
		run()
	}
	if *jsonOut {
		result := &JSONResult{Command: "init", Status: "ok", ExitCode: 0}
		if err != nil {
			result.Status = "error"
			result.ExitCode = exitCodeFor(err)
			if result.ExitCode == ExitOperational {
				// An outage is not a finding, in JSON as on the terminal.
				result.Status = "error"
			}
			result.Error = err.Error()
		}
		writeJSON(result)
		if err != nil {
			return &reportedError{code: result.ExitCode, err: err}
		}
		return nil
	}
	return err
}

func runCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	rootFlag := fs.String("root", "", "project root to compare against the baseline (default: the working directory)")
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	sarif := fs.String("sarif", "", "write findings as SARIF to this path (for GitHub code scanning)")
	timeout := fs.String("timeout", "", "overall time limit, e.g. 90s or 5m (0 disables)")
	verbose := fs.Bool("verbose", false, "show detailed resolution progress")
	if err := fs.Parse(args); err != nil {
		return err
	}

	limit, err := parseTimeout(*timeout)
	if err != nil {
		return err
	}
	ctx, cancel := withCommandDeadline(ctx, limit)
	defer cancel()

	logger := makeLogger(*verbose)

	var outcome checkOutcome
	run := func() {
		outcome, err = doCheckDetailed(ctx, logger, *rootFlag, *workflowDir, *lockfile, *sarif)
		err = classifyDeadline(ctx, err, limit)
	}
	if *jsonOut {
		humanToStderr(run)
	} else {
		run()
	}
	if *jsonOut {
		result := &JSONResult{Command: "check", Status: "ok", ExitCode: 0}
		result.Summary = &JSONSummary{Total: outcome.Total, Verified: outcome.Verified, Drifted: len(outcome.Results), Unverified: len(outcome.Warnings)}
		result.Drift = jsonDrift(outcome.Results)
		result.Unverified = outcome.Warnings
		if err != nil {
			result.Status = "drift_detected"
			result.ExitCode = exitCodeFor(err)
			if result.ExitCode == ExitOperational {
				// An outage is not a finding, in JSON as on the terminal.
				result.Status = "error"
			}
			result.Error = err.Error()
		}
		writeJSON(result)
		if err != nil {
			return &reportedError{code: result.ExitCode, err: err}
		}
		return nil
	}
	return err
}

func runUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	rootFlag := fs.String("root", "", "project root to scan (default: the repository root of -workflows, else the working directory)")
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	timeout := fs.String("timeout", "", "overall time limit, e.g. 90s or 5m (0 disables)")
	verbose := fs.Bool("verbose", false, "show detailed resolution progress")
	watch := fs.Bool("watch", false, "after writing, upload the lockfile so the platform watches its tools (needs a key)")
	repoFlag := fs.String("repo", "", "repository name for --watch (default: detected)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	limit, err := parseTimeout(*timeout)
	if err != nil {
		return err
	}
	ctx, cancel := withCommandDeadline(ctx, limit)
	defer cancel()

	logger := makeLogger(*verbose)
	if err := classifyDeadline(ctx, doUpdate(ctx, logger, *rootFlag, *workflowDir, *lockfile), limit); err != nil {
		return err
	}
	if *watch {
		return watchAfterWrite(ctx, *lockfile, *repoFlag)
	}
	return nil
}

func runScope(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scope", flag.ExitOnError)
	stepName := fs.String("step", "", "step name to scope (required)")
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	sanitize := fs.Bool("sanitize", false, "remove forbidden secrets from environment (not just report)")
	verbose := fs.Bool("verbose", false, "show detailed progress")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *stepName == "" {
		return fmt.Errorf("--step is required")
	}

	logger := makeLogger(*verbose)

	var outcome scopeOutcome
	var err error
	run := func() { outcome, err = doScopeDetailed(ctx, logger, *workflowDir, *stepName, *sanitize) }
	if *jsonOut {
		humanToStderr(run)
	} else {
		run()
	}
	if *jsonOut {
		result := &JSONResult{Command: "scope", Status: "ok", ExitCode: 0, Tool: outcome.Tool, ProfileSource: outcome.Source}
		for _, v := range outcome.Violations {
			result.Violations = append(result.Violations, JSONViolation{Step: *stepName, Secret: v.Secret, Pattern: v.Pattern, Reason: v.Reason, Tool: v.Tool})
		}
		if err != nil {
			result.Status = "violations_found"
			result.ExitCode = exitCodeFor(err)
			if result.ExitCode == ExitOperational {
				// An outage is not a finding, in JSON as on the terminal.
				result.Status = "error"
			}
			result.Error = err.Error()
		}
		writeJSON(result)
		if err != nil {
			return &reportedError{code: result.ExitCode, err: err}
		}
		return nil
	}
	return err
}

func runAudit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	timeout := fs.String("timeout", "", "overall time limit, e.g. 90s or 5m (0 disables)")
	verbose := fs.Bool("verbose", false, "show detailed progress")
	if err := fs.Parse(args); err != nil {
		return err
	}

	limit, err := parseTimeout(*timeout)
	if err != nil {
		return err
	}
	ctx, cancel := withCommandDeadline(ctx, limit)
	defer cancel()

	logger := makeLogger(*verbose)
	resolvers := buildResolvers()

	var outcome auditOutcome
	run := func() {
		outcome, err = doAuditDetailed(ctx, logger, *workflowDir, *lockfile, resolvers)
		err = classifyDeadline(ctx, err, limit)
	}
	if *jsonOut {
		humanToStderr(run)
	} else {
		run()
	}
	if *jsonOut {
		result := &JSONResult{Command: "audit", Status: "ok", ExitCode: 0}
		result.AuditDrift = jsonDrift(outcome.Drift)
		result.Unverified = outcome.Unverified
		for _, v := range outcome.Violations {
			result.AuditViolations = append(result.AuditViolations, JSONViolation{Step: v.StepName, Secret: v.Secret, Pattern: v.Pattern, Reason: v.Reason})
		}
		if err != nil {
			result.Status = "issues_found"
			result.ExitCode = exitCodeFor(err)
			if result.ExitCode == ExitOperational {
				// An outage is not a finding, in JSON as on the terminal.
				result.Status = "error"
			}
			result.Error = err.Error()
		}
		writeJSON(result)
		if err != nil {
			return &reportedError{code: result.ExitCode, err: err}
		}
		return nil
	}
	return err
}

func runIntel(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("intel", flag.ExitOnError)
	limit := fs.Int("limit", 20, "number of recent events to show")
	jsonOut := fs.Bool("json", false, "output events as JSON")
	watched := fs.Bool("watched", false, "events on the tools your organization watches (needs a key)")
	private := fs.Bool("private", false, "your organization's private feed (Enterprise; needs a key)")
	stix := fs.Bool("stix", false, "with --private: print the STIX 2.1 bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return classifyEntitlement(doIntel(ctx, intelOptions{limit: *limit, jsonOut: *jsonOut, watched: *watched, private: *private, stix: *stix}))
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Supply Chain Guardian — prevent supply chain attacks in CI/CD pipelines

Usage:
  scg <command> [flags]

Commands:
  init      Scan workflows, resolve dependencies, write scg.lock
  check     Validate scg.lock against live state
  update    Re-resolve all dependencies, update scg.lock
  scope     Audit and sanitize secrets for a specific step
  audit     Full security report (run in CI where secrets are injected)
  intel     Show threat-intel events: the public feed, --watched for your tools, --private (Enterprise)
  watch     Upload scg.lock so the platform watches its tools for drift (per repository)
  unwatch   Stop watching this repository (--repo NAME, or --all)
  watches   List what your organization watches
  login     Sign this machine in to your SCG organization (opens the browser)
  logout    Forget the key stored by login
  version   Print version information

Flags (all commands):
  --verbose             Show detailed resolution progress
  --json                Output results as JSON (machine-readable)
  --lockfile PATH       Lockfile path (default: scg.lock)
  --sarif PATH          Write findings as SARIF (check only, for code scanning)
  --timeout DURATION    Overall time limit, e.g. 90s or 5m (default 5m, 0 disables)
  --workflows DIR       Workflow directory (default: .github/workflows)

Environment:
  SCG_API_KEY        SCG Platform API key (CI; overrides the key stored by login)
  SCG_CONFIG_DIR     Where login stores credentials (default: the OS config dir, scg/)
  SCG_PLATFORM_URL   Platform URL (default: https://api.scg.data-insights.ai)

Examples:
  scg init                          # scan and lock all dependencies
  scg check                         # verify nothing has drifted
  scg check --verbose               # show resolution details
  scg scope --step trivy-scan       # audit secrets for a step
  scg audit                         # full security report
  scg intel --limit 50              # recent drift/burst events
  scg watch                         # watch this repository's lockfile for drift
  scg watches                       # what is watched, by repository

Exit codes:
  0   clean — everything verified
  1   finding — drift or a secret violation. Fail the build on this.
  2   operational — SCG could not complete the check (platform unreachable,
      rate limited, or its data was stale). Not a finding; retry.

Learn more: https://scg.data-insights.ai
`)
}
