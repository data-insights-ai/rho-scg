package main

import (
	"context"
	"os"

	"github.com/data-insights-ai/rho-scg/internal/config"
	"github.com/data-insights-ai/rho-scg/platform"
)

type intelOptions struct {
	limit   int
	jsonOut bool
	watched bool
	private bool
	stix    bool
}

// doIntel prints threat-intel events: the public feed by default, the
// organization's watched tools with --watched, its private feed with
// --private (as JSON, text or a STIX bundle).
func doIntel(ctx context.Context, o intelOptions) error {
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)

	switch {
	case o.private && o.stix:
		raw, err := client.PrivateIntelSTIX(ctx, o.limit)
		if err != nil {
			return err
		}
		outln(os.Stdout, string(raw))
		return nil
	case o.private:
		events, err := client.PrivateIntel(ctx, o.limit)
		if err != nil {
			return err
		}
		if o.jsonOut {
			return writeJSONValue(events)
		}
		if len(events) == 0 {
			outln(os.Stdout, "No events in your private feed.")
			return nil
		}
		for _, e := range events {
			repos := ""
			if len(e.Repos) > 0 {
				repos = "  [" + joinRepos(e.Repos) + "]"
			}
			outf(os.Stdout, "%s  [%-8s] %-14s %s — %s%s\n",
				e.Timestamp.UTC().Format("2006-01-02T15:04:05Z"), e.Severity, e.Type, e.Tool, e.Summary, repos)
		}
		return nil
	}

	var events []platform.IntelEvent
	var err error
	if o.watched {
		events, err = client.WatchedIntel(ctx, o.limit)
	} else {
		events, err = client.RecentIntel(ctx, o.limit)
	}
	if err != nil {
		return err
	}
	if o.jsonOut {
		return writeJSONValue(events)
	}
	if len(events) == 0 {
		outln(os.Stdout, "No recent intel events.")
		return nil
	}
	for _, e := range events {
		outf(os.Stdout, "%s  [%-8s] %-12s %s — %s\n",
			e.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			e.Severity, e.Type, e.Tool, e.Summary)
	}
	return nil
}

func joinRepos(repos []string) string {
	out := ""
	for i, r := range repos {
		if i > 0 {
			out += ", "
		}
		out += r
	}
	return out
}
