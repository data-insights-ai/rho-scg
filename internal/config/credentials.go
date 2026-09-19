package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credentials is what `scg login` stores: the key a command line was
// issued, the organization it belongs to, and where it came from. It lives
// in the user's config directory with owner-only permissions; SCG_API_KEY
// in the environment wins over it, so CI keeps injecting keys as before.
type Credentials struct {
	APIKey       string    `json:"api_key"`
	Organization string    `json:"organization"`
	PlatformURL  string    `json:"platform_url"`
	KeyPrefix    string    `json:"key_prefix"`
	SavedAt      time.Time `json:"saved_at"`
}

// CredentialsPath is where the credentials file lives:
// $SCG_CONFIG_DIR/credentials.json, else the OS config dir under scg/.
func CredentialsPath() (string, error) {
	if dir := os.Getenv("SCG_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "credentials.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no config directory: %w", err)
	}
	return filepath.Join(dir, "scg", "credentials.json"), nil
}

// LoadCredentials reads the stored credentials; a missing file is not an
// error and yields an empty value.
func LoadCredentials() (Credentials, error) {
	path, err := CredentialsPath()
	if err != nil {
		return Credentials{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Credentials{}, nil
	}
	if err != nil {
		return Credentials{}, err
	}
	var c Credentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return Credentials{}, fmt.Errorf("credentials file %s: %w", path, err)
	}
	return c, nil
}

// SaveCredentials writes the file with owner-only permissions, creating
// the directory as needed.
func SaveCredentials(c Credentials) (string, error) {
	path, err := CredentialsPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

// RemoveCredentials deletes the file; a missing file is fine.
func RemoveCredentials() (string, error) {
	path, err := CredentialsPath()
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return path, nil
}
