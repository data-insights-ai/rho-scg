package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/data-insights-ai/rho-scg/internal/config"
	"github.com/data-insights-ai/rho-scg/platform"
)

// doIntel fetches recent threat-intel events from the platform and prints them.
// The /v1/intel/recent feed is public, so no API key is required.
func doIntel(ctx context.Context, limit int, jsonOut bool) error {
	cfg := config.Load()
	client := platform.NewClient(cfg.PlatformBaseURL, cfg.PlatformAPIKey)

	events, err := client.RecentIntel(ctx, limit)
	if err != nil {
		return err
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(events)
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
