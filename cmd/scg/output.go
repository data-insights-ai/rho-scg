package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/data-insights-ai/rho-scg/manifest"
)

// JSONResult is the structured output format for --json mode.
type JSONResult struct {
	// SchemaVersion changes when a field is renamed or removed; additions
	// keep it. Consumers pin what they parse.
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	Status        string `json:"status"` // "ok", "drift_detected", "violations_found", "error"
	ExitCode      int    `json:"exit_code"`

	// Init fields
	Pipelines int `json:"pipelines,omitempty"`
	Tools     int `json:"tools,omitempty"`
	Steps     int `json:"steps,omitempty"`
	Secrets   int `json:"secrets,omitempty"`

	// Check fields
	Summary    *JSONSummary `json:"summary,omitempty"`
	Drift      []JSONDrift  `json:"drift,omitempty"`
	Unverified []string     `json:"unverified,omitempty"`

	// Scope fields
	Tool          string          `json:"tool,omitempty"`
	ProfileSource string          `json:"profile_source,omitempty"`
	Violations    []JSONViolation `json:"violations,omitempty"`

	// Audit fields
	AuditDrift      []JSONDrift     `json:"audit_drift,omitempty"`
	AuditViolations []JSONViolation `json:"audit_violations,omitempty"`

	// Error
	Error string `json:"error,omitempty"`
}

// jsonDrift converts drift findings for --json output.
func jsonDrift(results []manifest.DriftResult) []JSONDrift {
	var out []JSONDrift
	for _, d := range results {
		out = append(out, JSONDrift{Ecosystem: d.Ecosystem, Reference: d.Reference, LockedHash: d.LockedHash, LiveHash: d.LiveHash, Severity: strings.ToLower(d.Severity.String()), Detail: d.Detail})
	}
	return out
}

// JSONSummary counts what a check looked at.
type JSONSummary struct {
	Total      int `json:"total"`
	Verified   int `json:"verified"`
	Drifted    int `json:"drifted"`
	Unverified int `json:"unverified"`
}

// JSONDrift is a drift finding in JSON output.
type JSONDrift struct {
	Ecosystem  string `json:"ecosystem"`
	Reference  string `json:"reference"`
	LockedHash string `json:"locked_hash"`
	LiveHash   string `json:"live_hash"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail"`
}

// JSONViolation is a secret violation in JSON output.
type JSONViolation struct {
	Step    string `json:"step"`
	Secret  string `json:"secret"`
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
	Tool    string `json:"tool"`
}

// writeJSON writes the result as formatted JSON to stdout.
// jsonSchemaVersion is the current --json output schema.
const jsonSchemaVersion = 1

// machineOut is where --json writes: stdout as it was before humanToStderr
// diverted the human-readable report. A consumer parsing the output must
// get the JSON document and nothing else.
var machineOut io.Writer

// humanToStderr sends everything the command prints for people to stderr
// for the duration of fn, so --json leaves stdout to the JSON document.
func humanToStderr(fn func()) {
	saved := os.Stdout
	machineOut = saved
	os.Stdout = os.Stderr
	defer func() { os.Stdout = saved; machineOut = nil }()
	fn()
}

func writeJSON(result *JSONResult) {
	result.SchemaVersion = jsonSchemaVersion
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		outf(os.Stderr, "json marshal error: %v\n", err)
		return
	}
	w := machineOut
	if w == nil {
		w = os.Stdout
	}
	outln(w, string(data))
}

// Output helpers.
//
// Writes to stdout and stderr are deliberately unchecked: there is nowhere to
// report a failed write to the terminal, and a broken pipe (scg check | head)
// is normal, not an error worth surfacing. Routing every such write through
// these helpers documents that choice once, instead of leaving dozens of
// silently-dropped error returns that read like oversights.
func outf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func outln(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}
