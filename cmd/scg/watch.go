package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/data-insights-ai/rho-scg/internal/config"
	"github.com/data-insights-ai/rho-scg/internal/repo"
	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/platform"
)

// runWatch uploads the lockfile so the platform watches its tools for
// drift, attributed to this repository. Re-running replaces the
// repository's watch set; a tool that left the lockfile stops being watched.
func runWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	lockfile := fs.String("lockfile", "scg.lock", "lockfile path")
	repoFlag := fs.String("repo", "", "repository name (default: detected from CI variables or .git/config)")
	jsonOut := fs.Bool("json", false, "output the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)
	res, err := doWatch(ctx, client, *lockfile, *repoFlag)
	if err != nil {
		return classifyEntitlement(err)
	}
	if *jsonOut {
		return writeJSONValue(res)
	}
	printSuccess(os.Stdout, "Watching %d tools for %s (%d added, %d removed); %d repositories watched.",
		res.ToolsWatched, res.Repo, res.Added, res.Removed, res.ReposWatched)
	outln(os.Stdout, "  Drift on any of them goes to your organization's webhook and intel feed.")
	return nil
}

// doWatch reads and re-verifies the lockfile (an unsigned or foreign file
// is not something to watch on somebody's behalf) and uploads it.
func doWatch(ctx context.Context, client *platform.Client, lockfilePath, repoFlag string) (*platform.LockfileResponse, error) {
	if !client.IsConfigured() {
		return nil, operational("scg watch needs a key: run 'scg login' or set SCG_API_KEY")
	}
	lf, err := manifest.ReadLockfile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	if lf.Signature == nil {
		return nil, fmt.Errorf("lockfile is not signed — run 'scg init' first")
	}
	if err := manifest.VerifyLockfile(lf, manifest.NewPlatformVerifier()); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	name, err := repo.Detect(filepath.Dir(lockfilePath), repoFlag)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(lf)
	if err != nil {
		return nil, err
	}
	return client.UploadLockfile(ctx, raw, name)
}

// runUnwatch stops watching a repository, or everything.
func runUnwatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("unwatch", flag.ExitOnError)
	repoFlag := fs.String("repo", "", "repository to stop watching (default: detected)")
	all := fs.Bool("all", false, "stop watching every repository")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)
	if !client.IsConfigured() {
		return operational("scg unwatch needs a key: run 'scg login' or set SCG_API_KEY")
	}
	if *all {
		list, err := client.ListWatches(ctx, "")
		if err != nil {
			return classifyEntitlement(err)
		}
		n := 0
		for _, r := range list.Repos {
			if err := client.Unwatch(ctx, r.Repo, "", ""); err != nil && !errors.Is(err, platform.ErrNotFound) {
				return classifyEntitlement(err)
			}
			n++
		}
		printSuccess(os.Stdout, "Stopped watching %d repositories.", n)
		return nil
	}
	name, err := repo.Detect(".", *repoFlag)
	if err != nil {
		return err
	}
	if err := client.Unwatch(ctx, name, "", ""); err != nil {
		if errors.Is(err, platform.ErrNotFound) {
			return fmt.Errorf("%s is not watched", name)
		}
		return classifyEntitlement(err)
	}
	printSuccess(os.Stdout, "Stopped watching %s.", name)
	return nil
}

// runWatches lists what the organization watches.
func runWatches(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watches", flag.ExitOnError)
	repoFlag := fs.String("repo", "", "show the tools of one repository")
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)
	if !client.IsConfigured() {
		return operational("scg watches needs a key: run 'scg login' or set SCG_API_KEY")
	}
	list, err := client.ListWatches(ctx, *repoFlag)
	if err != nil {
		return classifyEntitlement(err)
	}
	if *jsonOut {
		return writeJSONValue(list)
	}
	if len(list.Repos) == 0 {
		outln(os.Stdout, "Nothing is watched yet. Run 'scg watch' in a repository with an scg.lock.")
		return nil
	}
	if *repoFlag == "" {
		outf(os.Stdout, "%s watches %d tools in %d repositories", list.Organization, list.Total, len(list.Repos))
		if list.RepoLimit > 0 {
			outf(os.Stdout, " (plan limit: %d)", list.RepoLimit)
		}
		outln(os.Stdout)
		for _, r := range list.Repos {
			name := r.Repo
			if name == "" {
				name = "(no repository)"
			}
			outf(os.Stdout, "  %-50s %4d tools   updated %s\n", name, r.Tools, r.UpdatedAt.UTC().Format("2006-01-02"))
		}
		return nil
	}
	for _, w := range list.Watches {
		outf(os.Stdout, "  %-14s %s\n", w.Ecosystem, w.Reference)
	}
	return nil
}

// classifyEntitlement turns a plan refusal into an operational exit: it is
// not a finding about the dependencies.
func classifyEntitlement(err error) error {
	if errors.Is(err, platform.ErrNotEntitled) || errors.Is(err, platform.ErrUnauthorized) {
		return operational("%w", err)
	}
	return err
}

func writeJSONValue(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// watchAfterWrite is init/update --watch: upload what was just written.
func watchAfterWrite(ctx context.Context, lockfilePath, repoFlag string) error {
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)
	res, err := doWatch(ctx, client, lockfilePath, repoFlag)
	if err != nil {
		return classifyEntitlement(err)
	}
	printSuccess(os.Stdout, "Watching %d tools for %s.", res.ToolsWatched, res.Repo)
	return nil
}
