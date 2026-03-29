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
func Load() *SCGConfig {
	return &SCGConfig{
		PlatformAPIKey:  os.Getenv("SCG_API_KEY"),
		PlatformBaseURL: envOrDefault("SCG_PLATFORM_URL", "https://api.scg.bds421.com"),
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
