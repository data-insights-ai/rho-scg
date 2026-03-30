// Command scg is the Supply Chain Guardian CLI.
//
// SCG prevents supply chain attacks by enforcing dependency integrity
// and secret least-privilege across CI/CD pipelines.
//
// All resolution goes through the SCG Platform (api.scg.bds421.com).
// No GitHub token, Docker Hub account, or registry credentials needed.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/internal/config"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/platform"
	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
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
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
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

// platformResolver creates a resolver that queries the SCG Platform.
// This is the ONLY way the CLI resolves dependencies. No local resolution.
func platformResolver(eco resolver.Ecosystem) resolver.Resolver {
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)
	return platform.NewPlatformResolver(client, eco)
}

func runInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	lockfile := fs.String("lockfile", "scg.lock", "output lockfile path")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	verbose := fs.Bool("verbose", false, "show detailed resolution progress")
	fs.Parse(args)

	logger := makeLogger(*verbose)
	res := platformResolver(resolver.EcoGitHubAction)

	err := doInit(ctx, logger, *workflowDir, *lockfile, res)
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
	noVerify := fs.Bool("no-verify", false, "skip signature verification (not recommended)")
	verbose := fs.Bool("verbose", false, "show detailed resolution progress")
	fs.Parse(args)

	logger := makeLogger(*verbose)

	err := doCheck(ctx, logger, *lockfile, *noVerify)
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
	verbose := fs.Bool("verbose", false, "show detailed resolution progress")
	fs.Parse(args)

	logger := makeLogger(*verbose)
	return doUpdate(ctx, logger, *workflowDir, *lockfile)
}

func runScope(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scope", flag.ExitOnError)
	stepName := fs.String("step", "", "step name to scope (required)")
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	sanitize := fs.Bool("sanitize", false, "remove forbidden secrets from environment (not just report)")
	verbose := fs.Bool("verbose", false, "show detailed progress")
	fs.Parse(args)

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
	verbose := fs.Bool("verbose", false, "show detailed progress")
	fs.Parse(args)

	logger := makeLogger(*verbose)
	res := platformResolver(resolver.EcoGitHubAction)

	err := doAudit(ctx, logger, *workflowDir, *lockfile, res)
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

func printUsage() {
	fmt.Fprint(os.Stderr, `Supply Chain Guardian — prevent supply chain attacks in CI/CD pipelines

Usage:
  scg <command> [flags]

Commands:
  init      Scan workflows, resolve dependencies, write scg.lock
  check     Validate scg.lock against live state (exit 0=clean, 1=drift)
  update    Re-resolve all dependencies, update scg.lock
  scope     Audit and sanitize secrets for a specific step
  audit     Full security report across all steps
  version   Print version information

Flags (all commands):
  --verbose             Show detailed resolution progress
  --json                Output results as JSON (machine-readable)
  --lockfile PATH       Lockfile path (default: scg.lock)
  --workflows DIR       Workflow directory (default: .github/workflows)

Environment:
  SCG_API_KEY        SCG Platform API key (higher rate limits, optional)
  SCG_PLATFORM_URL   Platform URL (default: https://api.scg.bds421.com)

Examples:
  scg init                          # scan and lock all dependencies
  scg check                         # verify nothing has drifted
  scg check --verbose               # show resolution details
  scg scope --step trivy-scan       # audit secrets for a step
  scg audit                         # full security report

Learn more: https://scg.bds421.com
`)
}
