package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/data-insights-ai/rho-scg/manifest"
)

// --json carries the findings themselves, not just a message: a drift
// entry names the tool, both hashes and a lower-case severity, and the
// summary counts what was looked at.
func TestJSONFindings(t *testing.T) {
	drift := jsonDrift([]manifest.DriftResult{{
		Ecosystem: "github_action", Reference: "actions/checkout@v4",
		LockedHash: "aaa", LiveHash: "bbb", Severity: manifest.SevCritical, Detail: "tag moved",
	}})
	if len(drift) != 1 || drift[0].Severity != "critical" || drift[0].LiveHash != "bbb" {
		t.Fatalf("drift = %+v", drift)
	}
	if jsonDrift(nil) != nil {
		t.Fatal("no findings must marshal as absent, not []")
	}
	res := &JSONResult{Command: "check", Status: "drift_detected", ExitCode: 1,
		Summary: &JSONSummary{Total: 3, Verified: 2, Drifted: 1}, Drift: drift, Unverified: []string{"x@1: rate limited"}}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"summary":{"total":3,"verified":2,"drifted":1,"unverified":0}`, `"severity":"critical"`, `"unverified":["x@1: rate limited"]`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("missing %s in %s", want, raw)
		}
	}
}
