package config

import (
	"testing"
)

// Configuration is where a deployment's security posture is actually decided,
// so the defaults have to be asserted rather than assumed.
func TestLoad_Defaults(t *testing.T) {
	for _, k := range []string{"SCG_API_KEY", "SCG_PLATFORM_URL", "SCG_LOG_LEVEL",
		"SCG_LOCKFILE", "SCG_WORKFLOW_DIR", "SCG_DATA_DIR"} {
		t.Setenv(k, "")
	}

	cfg := Load()

	if cfg.PlatformBaseURL != "https://scg.data-insights.ai" {
		t.Errorf("PlatformBaseURL = %q, want the production endpoint", cfg.PlatformBaseURL)
	}
	if cfg.LockfilePath != "scg.lock" {
		t.Errorf("LockfilePath = %q, want scg.lock", cfg.LockfilePath)
	}
	if cfg.WorkflowDir != ".github/workflows" {
		t.Errorf("WorkflowDir = %q, want .github/workflows", cfg.WorkflowDir)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.PlatformAPIKey != "" {
		t.Error("PlatformAPIKey must default to empty — anonymous access is the default tier")
	}
}

// The default platform URL must be https. The API key travels in a header, so
// a plaintext default would leak it on every request out of the box.
func TestLoad_DefaultPlatformURLIsHTTPS(t *testing.T) {
	t.Setenv("SCG_PLATFORM_URL", "")
	if got := Load().PlatformBaseURL; len(got) < 8 || got[:8] != "https://" {
		t.Errorf("default PlatformBaseURL = %q, want an https:// endpoint", got)
	}
}

func TestLoad_EnvironmentOverrides(t *testing.T) {
	t.Setenv("SCG_API_KEY", "scg_live_example")
	t.Setenv("SCG_PLATFORM_URL", "https://staging.example.com")
	t.Setenv("SCG_LOG_LEVEL", "debug")
	t.Setenv("SCG_LOCKFILE", "custom.lock")
	t.Setenv("SCG_WORKFLOW_DIR", "ci/")
	t.Setenv("SCG_DATA_DIR", "/var/scg")

	cfg := Load()

	tests := map[string][2]string{
		"PlatformAPIKey":  {cfg.PlatformAPIKey, "scg_live_example"},
		"PlatformBaseURL": {cfg.PlatformBaseURL, "https://staging.example.com"},
		"LogLevel":        {cfg.LogLevel, "debug"},
		"LockfilePath":    {cfg.LockfilePath, "custom.lock"},
		"WorkflowDir":     {cfg.WorkflowDir, "ci/"},
		"DataDir":         {cfg.DataDir, "/var/scg"},
	}
	for field, v := range tests {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", field, v[0], v[1])
		}
	}
}

// An empty variable must fall back to the default rather than blanking the
// setting — "" is how CI systems represent "unset", not "use nothing".
func TestEnvOrDefault_EmptyFallsBack(t *testing.T) {
	t.Setenv("SCG_TEST_EMPTY", "")
	if got := envOrDefault("SCG_TEST_EMPTY", "fallback"); got != "fallback" {
		t.Errorf("envOrDefault with an empty value = %q, want the fallback", got)
	}
	t.Setenv("SCG_TEST_SET", "value")
	if got := envOrDefault("SCG_TEST_SET", "fallback"); got != "value" {
		t.Errorf("envOrDefault = %q, want the set value", got)
	}
}

// Moving the default platform URL must not sign anybody out. A key saved
// by `scg login` names the host it was issued by, and the old host is the
// same platform under a different name — refusing it would have made the
// move look like an expired credential to every existing user.
func TestSavedCredentialsSurviveTheMoveToTheSiteOrigin(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"https://api.scg.data-insights.ai", "https://scg.data-insights.ai", true},
		{"https://scg.data-insights.ai", "https://scg.data-insights.ai", true},
		{"https://api.scg.data-insights.ai/", "https://scg.data-insights.ai", true},
		{"https://scg.data-insights.ai", "https://scg.example.invalid", false},
		{"https://api.scg.data-insights.ai", "http://localhost:8081", false},
	} {
		if got := SamePlatform(tc.a, tc.b); got != tc.same {
			t.Errorf("SamePlatform(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}
