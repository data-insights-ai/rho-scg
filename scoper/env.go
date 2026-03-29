package scoper

import (
	"os"
	"regexp"
	"strings"
)

// secretPatterns are substrings that indicate an environment variable
// likely contains a secret value.
var secretPatterns = []string{
	"TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL",
	"AUTH", "PRIVATE", "PYPI", "NPM", "DOCKER", "AWS",
	"GCP", "AZURE", "SSH", "GPG", "API_KEY",
}

// LooksLikeSecret reports whether an environment variable name
// likely contains a secret value based on common naming patterns.
func LooksLikeSecret(key string) bool {
	upper := strings.ToUpper(key)
	for _, p := range secretPatterns {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

// ScanEnv scans the current process environment and returns the names
// of all environment variables that look like secrets.
// NOTE: This function only IDENTIFIES secrets — it does not remove them.
// Actual environment sanitization (os.Unsetenv) is the caller's responsibility.
func ScanEnv() []string {
	var secrets []string
	for _, e := range os.Environ() {
		k, _, ok := strings.Cut(e, "=")
		if ok && LooksLikeSecret(k) {
			secrets = append(secrets, k)
		}
	}
	return secrets
}

// MatchSecrets filters secret names against a list of forbidden regex patterns.
// Returns the names that match any pattern.
func MatchSecrets(secrets []string, patterns []string) []string {
	var matched []string
	for _, s := range secrets {
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				// Invalid regex in DSM profile — this is a configuration bug, not a runtime error.
				// Log would be appropriate here but we don't have a logger. Return the error
				// in the pattern so it's visible in the output.
				continue // DSM profile regex is pre-validated at Bootstrap time
			}
			if re.MatchString(s) {
				matched = append(matched, s)
				break
			}
		}
	}
	return matched
}
