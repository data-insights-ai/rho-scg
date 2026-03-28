// Command scg is the Supply Chain Guardian CLI.
//
// SCG prevents supply chain attacks by enforcing dependency integrity
// and secret least-privilege across CI/CD pipelines.
//
// Usage:
//
//	scg init      Scan workflows, resolve dependencies, write scg.lock
//	scg check     Validate scg.lock against live state (exit 0=clean, 1=drift)
//	scg update    Re-resolve all dependencies, update scg.lock
//	scg scope     Audit and sanitize secrets for a specific step
//	scg audit     Full security report across all steps
//	scg version   Print version information
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(ctx, logger, os.Args[2:])
	case "check":
		err = runCheck(ctx, logger, os.Args[2:])
	case "update":
		err = runUpdate(ctx, logger, os.Args[2:])
	case "scope":
		err = runScope(ctx, logger, os.Args[2:])
	case "audit":
		err = runAudit(ctx, logger, os.Args[2:])
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
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func runInit(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	lockfile := fs.String("lockfile", "scg.lock", "output lockfile path")
	fs.Parse(args)

	ghToken := os.Getenv("GITHUB_TOKEN")
	res := resolver.NewGitHubResolver(ghToken)

	return doInit(ctx, logger, *workflowDir, *lockfile, res)
}

func runCheck(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	fs.Parse(args)

	ghToken := os.Getenv("GITHUB_TOKEN")

	return doCheck(ctx, logger, *lockfile, ghToken)
}

func runUpdate(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	fs.Parse(args)

	logger.Info("updating lockfile", "path", *lockfile)

	// TODO: implement
	// 1. Read existing lockfile
	// 2. Re-resolve all dependencies
	// 3. Update graph with new resolutions (close old RESOLVES_TO, create new)
	// 4. Regenerate and sign lockfile

	fmt.Println("scg update: not yet implemented")
	return nil
}

func runScope(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("scope", flag.ExitOnError)
	stepName := fs.String("step", "", "step name to scope (required)")
	fs.Parse(args)

	if *stepName == "" {
		return fmt.Errorf("--step is required")
	}

	logger.Info("scoping step", "step", *stepName)

	// TODO: implement
	// 1. Create graph and bootstrap DSM profiles
	// 2. Scan current environment for secrets
	// 3. Query graph for forbidden patterns for this step's tool
	// 4. Report violations and optionally sanitize environment

	fmt.Println("scg scope: not yet implemented")
	return nil
}

func runAudit(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	fs.Parse(args)

	logger.Info("auditing", "dir", *workflowDir)

	// TODO: implement
	// 1. Run init (scan + resolve)
	// 2. Run scope for each step
	// 3. Compile full report: drift + secret exposure

	fmt.Println("scg audit: not yet implemented")
	return nil
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

Environment:
  GITHUB_TOKEN       GitHub API token (for resolving action references)
  SCG_API_KEY        SCG Platform API key (enables pre-computed hashes and profiles)
  SCG_LOCKFILE       Lockfile path (default: scg.lock)
  SCG_WORKFLOW_DIR   Workflow directory (default: .github/workflows)
  SCG_LOG_LEVEL      Log level: debug, info, warn, error (default: info)

Examples:
  scg init                        # scan and lock all dependencies
  scg check                       # verify nothing has drifted (CI pre-step)
  scg scope --step trivy-scan     # sanitize secrets for a step
  scg audit                       # full security report

Learn more: https://github.com/bds421/supply-chain-guardian
`)
}
