package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DefaultCommandTimeout bounds how long a network-bound command may run.
//
// Without a ceiling, a hung or very slow platform stalls for the product of the
// per-request timeout, the retry count and the number of references: three
// retries of thirty seconds across fifty unique references is roughly nineteen
// minutes of a CI job spent learning nothing. A gate that can hang for that
// long is a gate teams put a `timeout-minutes` around and then start ignoring.
//
// The limit is generous enough for a large monorepo on a cold cache and short
// enough to fail inside a normal CI step.
const DefaultCommandTimeout = 5 * time.Minute

// withCommandDeadline bounds ctx unless timeout is zero, which disables it.
//
// The returned cancel must always be called.
func withCommandDeadline(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// classifyDeadline converts a timeout into an operational failure.
//
// A command that ran out of time detected nothing about the caller's
// dependencies, so it must not exit as though it had found something. The
// original error is preserved for the log; the user gets an instruction.
func classifyDeadline(ctx context.Context, err error, timeout time.Duration) error {
	if err == nil {
		return nil
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return operational(
		"timed out after %s: the SCG platform did not respond in time. "+
			"Nothing was detected about your dependencies. Retry, or raise --timeout",
		timeout)
}

// parseTimeout converts a flag value into a duration, rejecting negatives.
func parseTimeout(raw string) (time.Duration, error) {
	if raw == "" {
		return DefaultCommandTimeout, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid --timeout %q: %w", raw, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("invalid --timeout %q: must not be negative (use 0 to disable)", raw)
	}
	return d, nil
}
