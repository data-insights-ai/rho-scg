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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
)

var version = "dev"

func main() {
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
	lockfile := fs.String("lockfile", "scg.lock", "output lockfile path")
	jsonOut := fs.Bool("json", false, "output results as JSON")
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
	resolvers := buildResolvers()

	err = classifyDeadline(ctx, doInit(ctx, logger, *workflowDir, *lockfile, resolvers, newPlatformSigner()), limit)
	if *jsonOut {
		result := &JSONResult{Command: "init", Status: "ok", ExitCode: 0}
		if err != nil {
			result.Status = "error"
			result.ExitCode = 1
			result.Error = err.Error()
		}
		writeJSON(result)
		if err != nil {
			os.Exit(1)
		}
		return nil
	}
	return err
}

func runCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
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

	err = classifyDeadline(ctx, doCheck(ctx, logger, *lockfile, *sarif), limit)
	if *jsonOut {
		result := &JSONResult{Command: "check", Status: "ok", ExitCode: 0}
		if err != nil {
			result.Status = "drift_detected"
			result.ExitCode = 1
			result.Error = err.Error()
		}
		writeJSON(result)
		if err != nil {
			os.Exit(1)
		}
		return nil
	}
	return err
}

func runUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
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
	return classifyDeadline(ctx, doUpdate(ctx, logger, *workflowDir, *lockfile), limit)
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

	err := doScope(ctx, logger, *workflowDir, *stepName, *sanitize)
	if *jsonOut {
		result := &JSONResult{Command: "scope", Status: "ok", ExitCode: 0}
		if err != nil {
			result.Status = "violations_found"
			result.ExitCode = 1
			result.Error = err.Error()
		}
		writeJSON(result)
		if err != nil {
			os.Exit(1)
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

	err = classifyDeadline(ctx, doAudit(ctx, logger, *workflowDir, *lockfile, resolvers), limit)
	if *jsonOut {
		result := &JSONResult{Command: "audit", Status: "ok", ExitCode: 0}
		if err != nil {
			result.Status = "issues_found"
			result.ExitCode = 1
			result.Error = err.Error()
		}
		writeJSON(result)
		if err != nil {
			os.Exit(1)
		}
		return nil
	}
	return err
}

func runIntel(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("intel", flag.ExitOnError)
	limit := fs.Int("limit", 20, "number of recent events to show")
	jsonOut := fs.Bool("json", false, "output events as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return doIntel(ctx, *limit, *jsonOut)
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
  intel     Show recent threat-intel events (drift, bursts) from the platform
  version   Print version information

Flags (all commands):
  --verbose             Show detailed resolution progress
  --json                Output results as JSON (machine-readable)
  --lockfile PATH       Lockfile path (default: scg.lock)
  --sarif PATH          Write findings as SARIF (check only, for code scanning)
  --timeout DURATION    Overall time limit, e.g. 90s or 5m (default 5m, 0 disables)
  --workflows DIR       Workflow directory (default: .github/workflows)

Environment:
  SCG_API_KEY        SCG Platform API key (higher rate limits, optional)
  SCG_PLATFORM_URL   Platform URL (default: https://api.scg.data-insights.ai)

Examples:
  scg init                          # scan and lock all dependencies
  scg check                         # verify nothing has drifted
  scg check --verbose               # show resolution details
  scg scope --step trivy-scan       # audit secrets for a step
  scg audit                         # full security report
  scg intel --limit 50              # recent drift/burst events

Exit codes:
  0   clean — everything verified
  1   finding — drift or a secret violation. Fail the build on this.
  2   operational — SCG could not complete the check (platform unreachable,
      rate limited, or its data was stale). Not a finding; retry.

Learn more: https://scg.data-insights.ai
`)
}
