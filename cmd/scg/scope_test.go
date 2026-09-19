package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// scope is the command that runs immediately before a step executes with real
// secrets in the environment, so its verdicts have to be right.
func TestDoScope_NoViolations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"tool":"actions/checkout","risk_tier":1,
			"required_secrets":[],"forbidden_patterns":[{"pattern":"^NEVER_SET_ANYWHERE_XYZ$","reason":"n/a"}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)

	if err := doScope(context.Background(), quietLogger(), testdataDir(), "checkout", false); err != nil {
		t.Fatalf("a step with no forbidden secrets present must pass: %v", err)
	}
}

// The finding that matters: a secret the step must not see, present in the
// environment, has to be reported.
func TestDoScope_ReportsViolation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"tool":"actions/checkout","risk_tier":3,
			"required_secrets":[],
			"forbidden_patterns":[{"pattern":"^SCG_SCOPE_TEST_TOKEN$","reason":"checkout needs no registry token"}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)
	t.Setenv("SCG_SCOPE_TEST_TOKEN", "leak-me")

	err := doScope(context.Background(), quietLogger(), testdataDir(), "checkout", false)
	if err == nil {
		t.Fatal("a forbidden secret present in the environment must be a violation")
	}
	if strings.Contains(err.Error(), "leak-me") {
		t.Error("the secret VALUE must never appear in output; only its name")
	}
}

// --sanitize must actually remove the variable. Reporting that it was removed
// while leaving it in the environment would be the worst possible outcome: the
// step runs with the secret AND the operator believes it does not.
func TestDoScope_SanitizeRemovesTheSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"tool":"actions/checkout","risk_tier":3,
			"required_secrets":[],
			"forbidden_patterns":[{"pattern":"^SCG_SANITIZE_TEST_TOKEN$","reason":"not needed"}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)
	t.Setenv("SCG_SANITIZE_TEST_TOKEN", "remove-me")

	_ = doScope(context.Background(), quietLogger(), testdataDir(), "checkout", true)

	if v, ok := os.LookupEnv("SCG_SANITIZE_TEST_TOKEN"); ok {
		t.Errorf("--sanitize left the forbidden secret in the environment (value still %q)", v)
	}
}

// A step that does not exist is a usage error the operator must see, not a
// silent pass that looks like approval.
func TestDoScope_UnknownStep(t *testing.T) {
	if err := doScope(context.Background(), quietLogger(), testdataDir(), "no-such-step", false); err == nil {
		t.Fatal("an unknown step name must be an error, not a silent pass")
	}
}

func TestDoScope_MissingWorkflowDir(t *testing.T) {
	if err := doScope(context.Background(), quietLogger(), t.TempDir()+"/absent", "x", false); err == nil {
		t.Fatal("a missing workflow directory must be an error")
	}
}
