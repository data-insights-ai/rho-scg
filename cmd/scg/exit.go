package main

import (
	"errors"
	"fmt"
)

// Exit codes. A CI gate has to distinguish "your supply chain changed" from
// "our service was unreachable", and previously both left through the same
// generic error path as exit 1. Since SCG deliberately has no local fallback,
// that made every platform outage look identical to an attack on every
// customer's pipeline simultaneously.
const (
	// ExitClean means everything verified.
	ExitClean = 0
	// ExitFinding means a real security finding: drift, or a secret violation.
	// This is the code to fail a build on and to page someone about.
	ExitFinding = 1
	// ExitOperational means SCG could not complete the check — the platform was
	// unreachable, the budget was spent, the data was stale. It says nothing
	// about the supply chain. Retry it; do not treat it as a detection.
	ExitOperational = 2
	// ExitUsage means the command was invoked wrongly.
	ExitUsage = 64
)

// OperationalError marks a failure as an SCG problem rather than a finding
// about the user's dependencies.
type OperationalError struct{ Err error }

func (e *OperationalError) Error() string { return e.Err.Error() }
func (e *OperationalError) Unwrap() error { return e.Err }

// operational wraps err as an operational failure.
func operational(format string, args ...any) error {
	return &OperationalError{Err: fmt.Errorf(format, args...)}
}

// exitCodeFor maps an error to the process exit code.
func exitCodeFor(err error) int {
	if err == nil {
		return ExitClean
	}
	var opErr *OperationalError
	if errors.As(err, &opErr) {
		return ExitOperational
	}
	return ExitFinding
}
