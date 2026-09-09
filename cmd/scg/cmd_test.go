package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/data-insights-ai/rho-scg/manifest"
	"github.com/data-insights-ai/rho-scg/platform"
	"github.com/data-insights-ai/rho-scg/resolver"
)

// A signed, verifying lockfile with no drift must exit clean.
func TestDoCheck_CleanRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scg.lock")

	signer := testSigner(t)
	lf := lockfileWith(manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "actions/checkout@v4",
		Hash: "abc123", Algorithm: "sha1",
	})
	if err := signer.SignLockfile(context.Background(), lf); err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}

	// Point the CLI at a platform that agrees with the lockfile.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"hash":"abc123","algorithm":"sha1","stale":false}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)

	if err := doCheck(context.Background(), quietLogger(), path, ""); err != nil {
		t.Fatalf("a clean lockfile must verify: %v", err)
	}
}

// An unsigned lockfile must be refused outright.
func TestDoCheck_RejectsUnsignedLockfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scg.lock")

	lf := lockfileWith(manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "x@v1", Hash: "h", Algorithm: "sha1",
	})
	if err := manifest.WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}

	err := doCheck(context.Background(), quietLogger(), path, "")
	if err == nil {
		t.Fatal("an unsigned lockfile must not verify")
	}
	if !strings.Contains(err.Error(), "not signed") {
		t.Errorf("error should say the lockfile is unsigned, got: %v", err)
	}
}

// The tamper-then-resign attack, end to end through doCheck.
func TestDoCheck_RejectsForeignSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scg.lock")

	_, attackerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lf := lockfileWith(manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "x@v1",
		Hash: "deadbeef", Algorithm: "sha1",
	})
	data, err := manifest.CanonicalJSON(lf)
	if err != nil {
		t.Fatal(err)
	}
	pub := attackerKey.Public().(ed25519.PublicKey)
	lf.Signature = &manifest.Signature{
		Algorithm: manifest.AlgorithmPlatform,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(attackerKey, data)),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	if err := manifest.WriteLockfile(path, lf); err != nil {
		t.Fatal(err)
	}

	if err := doCheck(context.Background(), quietLogger(), path, ""); err == nil {
		t.Fatal("a lockfile signed by an attacker-generated key must not verify")
	}
}

// A missing lockfile is an ordinary, explainable failure.
func TestDoCheck_MissingLockfile(t *testing.T) {
	err := doCheck(context.Background(), quietLogger(), filepath.Join(t.TempDir(), "absent.lock"), "")
	if err == nil {
		t.Fatal("a missing lockfile must be an error")
	}
}

func TestBuildResolvers_CoversEveryLockedEcosystem(t *testing.T) {
	resolvers := buildResolvers()
	for _, eco := range []resolver.Ecosystem{
		resolver.EcoGitHubAction, resolver.EcoDocker, resolver.EcoPyPI, resolver.EcoNPM,
	} {
		r, ok := resolvers[eco]
		if !ok {
			t.Errorf("no resolver for %q; entries in that ecosystem would go unchecked", eco)
			continue
		}
		if r.Ecosystem() != eco {
			t.Errorf("resolver for %q reports ecosystem %q", eco, r.Ecosystem())
		}
	}
}

// signViaPlat must refuse a signature this build cannot anchor, rather than
// storing it and deferring the failure to someone else's check.
func TestSignViaPlat_RejectsUnanchorableAlgorithm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"algorithm":"ed25519","value":"v","public_key":"p"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	c := platform.NewClient(srv.URL, "")
	lf := lockfileWith(manifest.ToolEntry{Ecosystem: "github_action", Reference: "x@v1", Hash: "h"})

	err := signViaPlat(context.Background(), c, lf)
	if err == nil {
		t.Fatal("a non-platform signature algorithm must be refused")
	}
	if lf.Signature != nil {
		t.Error("a refused signature must not be stored on the lockfile")
	}
}

func TestSignViaPlat_StoresPlatformSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"algorithm":"ed25519-platform","key_id":"k","value":"v","public_key":"p"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	c := platform.NewClient(srv.URL, "")
	lf := lockfileWith(manifest.ToolEntry{Ecosystem: "github_action", Reference: "x@v1", Hash: "h"})

	if err := signViaPlat(context.Background(), c, lf); err != nil {
		t.Fatal(err)
	}
	if lf.Signature == nil || lf.Signature.Algorithm != manifest.AlgorithmPlatform {
		t.Errorf("signature = %+v", lf.Signature)
	}
}

func TestDoIntel_RendersEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`[{"id":"e1","type":"drift","severity":"critical",
			"ecosystem":"github_action","tool":"actions/checkout@v4","summary":"tag moved"}]`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)

	if err := doIntel(context.Background(), 5, false); err != nil {
		t.Fatalf("doIntel: %v", err)
	}
	if err := doIntel(context.Background(), 5, true); err != nil {
		t.Fatalf("doIntel --json: %v", err)
	}
}

func TestCompileForbidden(t *testing.T) {
	good, err := compileForbidden([]platform.ForbiddenSpec{
		{Pattern: `^AWS_`, Reason: "no cloud creds"},
		{Pattern: `_TOKEN$`, Reason: "no tokens"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(good) != 2 {
		t.Fatalf("compiled %d patterns, want 2", len(good))
	}

	// Order must be preserved so a match can be attributed to the right rule.
	if !good[0].MatchString("AWS_SECRET_ACCESS_KEY") || good[0].MatchString("NPM_TOKEN") {
		t.Error("compiled patterns are out of order")
	}

	if _, err := compileForbidden([]platform.ForbiddenSpec{{Pattern: "([unclosed"}}); err == nil {
		t.Fatal("an invalid profile pattern must be a hard error, not a silent skip")
	}
}

// JSON output is what CI consumes; a malformed document breaks every
// integration downstream.
func TestWriteJSON_IsValidJSON(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	writeJSON(&JSONResult{Command: "check", Status: "ok", ExitCode: ExitClean})
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}

	var got JSONResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("writeJSON produced invalid JSON: %v\n%s", err, buf.String())
	}
	if got.Command != "check" || got.ExitCode != ExitClean {
		t.Errorf("round-tripped to %+v", got)
	}
}

// The printers must not panic on any severity, and must write something.
func TestPrinters(t *testing.T) {
	var buf bytes.Buffer
	printSuccess(&buf, "ok %d", 1)
	printFailure(&buf, "bad %s", "thing")
	printWarning(&buf, "careful")
	if buf.Len() == 0 {
		t.Fatal("the printers wrote nothing")
	}
	for _, want := range []string{"ok 1", "bad thing", "careful"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output is missing %q:\n%s", want, buf.String())
		}
	}
}

// Colour helpers must be pure string decoration — never dropping the content.
func TestColorHelpersPreserveText(t *testing.T) {
	for name, fn := range map[string]func(string) string{
		"red": red, "yellow": yellow, "cyan": cyan, "dim": dim, "bold": bold,
	} {
		if got := fn("payload"); !strings.Contains(got, "payload") {
			t.Errorf("%s() dropped its text: %q", name, got)
		}
	}
	if crossMark() == "" || warnMark() == "" || checkMark() == "" {
		t.Error("status marks must not be empty")
	}
}

func TestOperationalError_Message(t *testing.T) {
	err := operational("platform returned %d", 503)
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("Error() = %q, want it to carry the detail", err.Error())
	}
}

// audit is the command teams run in CI where secrets are actually present, so
// it has to work end to end without a lockfile as well as with one.
func TestDoAudit_WithoutLockfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"tool":"actions/checkout","risk_tier":1,
			"required_secrets":[],"forbidden_patterns":[]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)

	mock := newMockResolver()
	err := doAudit(context.Background(), quietLogger(), testdataDir(),
		filepath.Join(t.TempDir(), "absent.lock"),
		map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: mock})
	if err != nil {
		t.Fatalf("audit with no lockfile must still run: %v", err)
	}
}

// A forbidden secret that is actually present in the environment is a finding,
// and audit must report it rather than exit clean.
func TestDoAudit_ReportsForbiddenSecretInEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"tool":"actions/checkout","risk_tier":3,
			"required_secrets":[],
			"forbidden_patterns":[{"pattern":"^SCG_AUDIT_TEST_TOKEN$","reason":"not needed by checkout"}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)
	t.Setenv("SCG_AUDIT_TEST_TOKEN", "super-secret-value")

	mock := newMockResolver()
	err := doAudit(context.Background(), quietLogger(), testdataDir(),
		filepath.Join(t.TempDir(), "absent.lock"),
		map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: mock})
	if err == nil {
		t.Fatal("a forbidden secret present in the environment must be reported")
	}
	// The value must never appear in the message; only the name.
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Error("the secret VALUE must never be echoed, only its name")
	}
}

// A malformed profile pattern is an operational failure, not a clean run: the
// control could not be applied, so nothing was actually checked.
func TestDoAudit_MalformedProfilePatternIsOperational(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"tool":"actions/checkout","risk_tier":3,
			"required_secrets":[],
			"forbidden_patterns":[{"pattern":"([unclosed","reason":"broken rule"}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)

	mock := newMockResolver()
	err := doAudit(context.Background(), quietLogger(), testdataDir(),
		filepath.Join(t.TempDir(), "absent.lock"),
		map[resolver.Ecosystem]resolver.Resolver{resolver.EcoGitHubAction: mock})
	if err == nil {
		t.Fatal("a profile with an uncompilable pattern must not report a clean audit")
	}
	if exitCodeFor(err) != ExitOperational {
		t.Errorf("exit code = %d, want %d — a broken rule is our problem, not a finding",
			exitCodeFor(err), ExitOperational)
	}
}

func TestDoAudit_MissingWorkflowDir(t *testing.T) {
	err := doAudit(context.Background(), quietLogger(),
		filepath.Join(t.TempDir(), "no-such-dir"), "scg.lock",
		map[resolver.Ecosystem]resolver.Resolver{})
	if err == nil {
		t.Fatal("a missing workflow directory must be an error")
	}
}

// SARIF is what puts findings in a repository's Security tab instead of only
// in a job log that rotates away.
func TestWriteSARIF_IsValidAndCarriesFindings(t *testing.T) {
	var buf bytes.Buffer
	drift := []manifest.DriftResult{{
		Ecosystem:  "github_action",
		Reference:  "actions/checkout@v4",
		LockedHash: "34e114876b0b",
		LiveHash:   "11d5960a3267",
		Severity:   manifest.SevCritical,
	}}
	warnings := []string{"github/codeql-action@v3 — platform data is stale"}

	if err := writeSARIF(&buf, "scg.lock", drift, warnings); err != nil {
		t.Fatal(err)
	}

	var report struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, buf.String())
	}

	if report.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(report.Runs))
	}
	run := report.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("got %d results, want 2 (one drift, one warning)", len(run.Results))
	}

	// Drift must be an error; an unverifiable entry must be a warning. Marking
	// "we could not look" as an error would put an SCG outage in the Security
	// tab as if it were an attack.
	byRule := map[string]string{}
	for _, r := range run.Results {
		byRule[r.RuleID] = r.Level
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "scg.lock" {
			t.Errorf("result %s has no usable location", r.RuleID)
		}
	}
	if byRule[ruleDrift] != "error" {
		t.Errorf("drift level = %q, want error", byRule[ruleDrift])
	}
	if byRule[ruleStale] != "warning" {
		t.Errorf("unverified level = %q, want warning", byRule[ruleStale])
	}

	// Every rule referenced by a result must be declared, or GitHub drops it.
	declared := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		declared[r.ID] = true
	}
	for id := range byRule {
		if !declared[id] {
			t.Errorf("result references rule %q which the driver does not declare", id)
		}
	}
}

// A clean run must still produce a well-formed report with an empty results
// array — a missing array reads as a malformed run, not as "no findings".
func TestWriteSARIF_CleanRunHasEmptyResultsArray(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSARIF(&buf, "scg.lock", nil, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Errorf("a clean run must emit an empty results array, got:\n%s", buf.String())
	}
}

func TestDoCheck_WritesSARIFFile(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "scg.lock")
	sarifPath := filepath.Join(dir, "scg.sarif")

	signer := testSigner(t)
	lf := lockfileWith(manifest.ToolEntry{
		Ecosystem: "github_action", Reference: "actions/checkout@v4",
		Hash: "locked", Algorithm: "sha1",
	})
	if err := signer.SignLockfile(context.Background(), lf); err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteLockfile(lockPath, lf); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"hash":"MOVED","algorithm":"sha1","stale":false}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	t.Setenv("SCG_PLATFORM_URL", srv.URL)

	// Drift is expected; the report must be written regardless.
	_ = doCheck(context.Background(), quietLogger(), lockPath, sarifPath)

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("SARIF file was not written: %v", err)
	}
	if !strings.Contains(string(data), ruleDrift) {
		t.Errorf("SARIF report does not contain the drift finding:\n%s", data)
	}
}
