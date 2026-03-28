package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// JSONResult is the structured output format for --json mode.
type JSONResult struct {
	Command  string `json:"command"`
	Status   string `json:"status"` // "ok", "drift_detected", "violations_found", "error"
	ExitCode int    `json:"exit_code"`

	// Init fields
	Pipelines int `json:"pipelines,omitempty"`
	Tools     int `json:"tools,omitempty"`
	Steps     int `json:"steps,omitempty"`
	Secrets   int `json:"secrets,omitempty"`

	// Check fields
	Drift []JSONDrift `json:"drift,omitempty"`

	// Scope fields
	Violations []JSONViolation `json:"violations,omitempty"`

	// Audit fields
	AuditDrift      []JSONDrift     `json:"audit_drift,omitempty"`
	AuditViolations []JSONViolation `json:"audit_violations,omitempty"`

	// Error
	Error string `json:"error,omitempty"`
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
func writeJSON(result *JSONResult) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
		return
	}
	fmt.Fprintln(os.Stdout, string(data))
}
