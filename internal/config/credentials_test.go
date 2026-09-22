package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCredentialsRoundTripAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SCG_CONFIG_DIR", dir)
	t.Setenv("SCG_API_KEY", "")
	t.Setenv("SCG_PLATFORM_URL", "")
	if c, err := LoadCredentials(); err != nil || c.APIKey != "" {
		t.Fatalf("missing file = %+v, %v", c, err)
	}
	path, err := SaveCredentials(Credentials{APIKey: "scg_x_y", Organization: "acme", PlatformURL: "https://scg.data-insights.ai", SavedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "credentials.json") {
		t.Fatalf("path = %s", path)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %v, %v", info.Mode(), err)
	}
	if Load().PlatformAPIKey != "scg_x_y" {
		t.Fatal("stored key not used")
	}
	t.Setenv("SCG_API_KEY", "scg_env")
	if Load().PlatformAPIKey != "scg_env" {
		t.Fatal("environment must win")
	}
	t.Setenv("SCG_API_KEY", "")
	t.Setenv("SCG_PLATFORM_URL", "https://other.example.test")
	if Load().PlatformAPIKey != "" {
		t.Fatal("a key from another platform must not be sent elsewhere")
	}
	t.Setenv("SCG_PLATFORM_URL", "")
	if _, err := RemoveCredentials(); err != nil {
		t.Fatal(err)
	}
	if Load().PlatformAPIKey != "" {
		t.Fatal("removed key still used")
	}
	if _, err := RemoveCredentials(); err != nil {
		t.Fatalf("removing twice: %v", err)
	}
}
