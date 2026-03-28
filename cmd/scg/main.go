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
	jsonOut := fs.Bool("json", false, "output results as JSON")
	fs.Parse(args)

	ghToken := os.Getenv("GITHUB_TOKEN")
	res := resolver.NewGitHubResolver(ghToken)

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

func runCheck(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	strict := fs.Bool("strict", false, "fail-closed: reject unsigned lockfiles, treat warnings as errors")
	fs.Parse(args)

	ghToken := os.Getenv("GITHUB_TOKEN")

	err := doCheck(ctx, logger, *lockfile, ghToken, *strict)
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

func runUpdate(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	fs.Parse(args)

	return doUpdate(ctx, logger, *workflowDir, *lockfile)
}

func runScope(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("scope", flag.ExitOnError)
	stepName := fs.String("step", "", "step name to scope (required)")
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	strict := fs.Bool("strict", false, "fail-closed: treat warnings as errors")
	fs.Parse(args)

	if *stepName == "" {
		return fmt.Errorf("--step is required")
	}

	ghToken := os.Getenv("GITHUB_TOKEN")
	res := resolver.NewGitHubResolver(ghToken)

	err := doScope(ctx, logger, *workflowDir, *stepName, res, *strict)
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

func runAudit(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	workflowDir := fs.String("workflows", ".github/workflows", "workflow directory to scan")
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	jsonOut := fs.Bool("json", false, "output results as JSON")
	fs.Parse(args)

	ghToken := os.Getenv("GITHUB_TOKEN")
	res := resolver.NewGitHubResolver(ghToken)

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
  --json              Output results as JSON (machine-readable)
  --workflows DIR     Workflow directory (default: .github/workflows)
  --lockfile PATH     Lockfile path (default: scg.lock)

Environment:
  GITHUB_TOKEN       GitHub API token (for resolving action references)
  SCG_API_KEY        SCG Platform API key (enables pre-computed hashes and profiles)

Examples:
  scg init                          # scan and lock all dependencies
  scg check                         # verify nothing has drifted (CI pre-step)
  scg check --json                  # machine-readable drift check
  scg scope --step trivy-scan       # audit secrets for a step
  scg audit                         # full security report

Learn more: https://github.com/bds421/supply-chain-guardian
`)
}
