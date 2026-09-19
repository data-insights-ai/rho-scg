// Package config defines the SCG configuration model.
package config

import "os"

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
	baseURL := envOrDefault("SCG_PLATFORM_URL", "https://api.scg.data-insights.ai")
	apiKey := os.Getenv("SCG_API_KEY")
	if apiKey == "" {
		if creds, err := LoadCredentials(); err == nil && creds.APIKey != "" && (creds.PlatformURL == "" || creds.PlatformURL == baseURL) {
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

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
