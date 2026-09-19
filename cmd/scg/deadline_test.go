package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/data-insights-ai/rho-scg/manifest"
)

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "", want: DefaultCommandTimeout},
		{in: "90s", want: 90 * time.Second},
		{in: "5m", want: 5 * time.Minute},
		{in: "0", want: 0}, // explicit opt-out
		{in: "-1s", wantErr: true},
		{in: "soon", wantErr: true},
		{in: "5", wantErr: true}, // no unit
	}
	for _, tt := range tests {
		got, err := parseTimeout(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseTimeout(%q) = %v, want an error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTimeout(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseTimeout(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestWithCommandDeadline(t *testing.T) {
	ctx, cancel := withCommandDeadline(context.Background(), 50*time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Errorf("ctx.Err() = %v, want DeadlineExceeded", ctx.Err())
	}

	// Zero disables the limit: the context must stay live.
	noLimit, cancel2 := withCommandDeadline(context.Background(), 0)
	defer cancel2()
	if _, ok := noLimit.Deadline(); ok {
		t.Error("a zero timeout must not set a deadline")
	}
}

// A command that ran out of time detected nothing about the caller's
// dependencies. Exiting 1 would report an SCG timeout as a supply chain
// finding — the same conflation the exit-code split exists to prevent.
func TestClassifyDeadline_TimeoutIsOperational(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()

	err := classifyDeadline(ctx, errors.New("resolve failed"), 5*time.Minute)
	if err == nil {
		t.Fatal("expected an error")
	}
	if exitCodeFor(err) != ExitOperational {
		t.Errorf("exit code = %d, want %d", exitCodeFor(err), ExitOperational)
	}
	if !strings.Contains(err.Error(), "Nothing was detected") {
		t.Errorf("the message must say nothing was detected, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--timeout") {
		t.Errorf("the message should say how to raise the limit, got: %v", err)
	}
}

// A genuine finding must survive unchanged. Wrapping drift as a timeout would
// hide a real detection.
func TestClassifyDeadline_PreservesRealFindings(t *testing.T) {
	drift := errors.New("drift detected: 1 tool(s) changed")

	got := classifyDeadline(context.Background(), drift, 5*time.Minute)
	if !errors.Is(got, drift) {
		t.Errorf("a finding must pass through, got %v", got)
	}
	// And it must not be re-labelled as operational, which would demote a real
	// detection to "retry this".
	var opErr *OperationalError
	if errors.As(got, &opErr) {
		t.Error("a finding must not be wrapped as an operational failure")
	}
	if exitCodeFor(got) != ExitFinding {
		t.Errorf("exit code = %d, want %d", exitCodeFor(got), ExitFinding)
	}
}

func TestClassifyDeadline_NilStaysNil(t *testing.T) {
	if err := classifyDeadline(context.Background(), nil, time.Minute); err != nil {
		t.Errorf("a clean run must stay clean, got %v", err)
	}
}

// A slow platform must surface as a timeout rather than stalling the job. The
// exercise runs through doCheck so the deadline is proven to reach the
// network path, not just the helper.
func TestDoCheck_HonoursDeadline(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/scg.lock"

	signer := testSigner(t)
	lf := lockfileWith(manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "actions/checkout@v4",
		Hash: "abc", Algorithm: "sha1",
	})
	if err := signer.SignLockfile(context.Background(), lf); err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}

	// A server that never answers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)

	ctx, cancel := withCommandDeadline(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := classifyDeadline(ctx, doCheck(ctx, quietLogger(), path, ""), 300*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a platform that never answers must not produce a clean check")
	}
	if exitCodeFor(err) != ExitOperational {
		t.Errorf("exit code = %d, want %d — a stall is not a finding", exitCodeFor(err), ExitOperational)
	}
	if elapsed > 10*time.Second {
		t.Errorf("took %v; the deadline did not bound the run", elapsed)
	}
}
