// Package config defines the SCG configuration model.
package config

import (
	"os"
	"strings"
)

// SCGConfig holds all SCG configuration values.
type SCGConfig struct {
	// PlatformAPIKey for higher rate limits (optional, 20/hr without).
	PlatformAPIKey string

	// PlatformBaseURL is the SCG platform API endpoint.
	PlatformBaseURL string

	// LogLevel controls log verbosity (debug, info, warn, error).
	LogLevel string

	// LockfilePath is the path to the scg.lock file.
	LockfilePath string

	// WorkflowDir is the directory containing CI/CD workflow files.
	WorkflowDir string

	// DataDir is the directory for persistent graph storage (daemon mode).
	DataDir string
}

// Load reads configuration from environment variables with sensible defaults.
// The API key comes from SCG_API_KEY, or else from the credentials `scg
// login` stored, when they were issued by the same platform.
func Load() *SCGConfig {
	baseURL := envOrDefault("SCG_PLATFORM_URL", "https://scg.data-insights.ai")
	apiKey := os.Getenv("SCG_API_KEY")
	if apiKey == "" {
		if creds, err := LoadCredentials(); err == nil && creds.APIKey != "" && (creds.PlatformURL == "" || SamePlatform(creds.PlatformURL, baseURL)) {
			apiKey = creds.APIKey
		}
	}
	return &SCGConfig{
		PlatformAPIKey:  apiKey,
		PlatformBaseURL: baseURL,
		LogLevel:        envOrDefault("SCG_LOG_LEVEL", "info"),
		LockfilePath:    envOrDefault("SCG_LOCKFILE", "scg.lock"),
		WorkflowDir:     envOrDefault("SCG_WORKFLOW_DIR", ".github/workflows"),
		DataDir:         os.Getenv("SCG_DATA_DIR"),
	}
}

// LegacyPlatformURL is where this CLI used to send everything. The API is
// now served from the site's own origin, and that host remains a permanent
// alias, because every binary released before the move has it compiled in.
const LegacyPlatformURL = "https://api.scg.data-insights.ai"

// SamePlatform reports whether two platform URLs name the same deployment.
//
// A key is only read from the credentials file when it was issued by the
// platform being addressed: a key sent to somebody else's platform is a
// key given away. That check was a string comparison, and changing the
// default URL would therefore have signed out everybody who had ever run
// `scg login` — their saved key names the old host, which is the same
// platform reached by a different name.
func SamePlatform(a, b string) bool {
	return canonicalPlatform(a) == canonicalPlatform(b)
}

func canonicalPlatform(u string) string {
	u = strings.TrimRight(strings.TrimSpace(u), "/")
	if u == LegacyPlatformURL {
		return "https://scg.data-insights.ai"
	}
	return u
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
