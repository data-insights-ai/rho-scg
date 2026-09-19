package scoper

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// secretTokens are the word-like fragments that mark an environment variable as
// carrying a credential.
//
// These are matched against the variable name split into words, not as bare
// substrings. Substring matching flagged MONKEY, DONKEY, KEYBOARD (all contain
// "KEY") and AUTHOR (contains "AUTH") as secrets, and an audit that cries wolf
// on ordinary variables is one people stop reading.
var secretTokens = map[string]bool{
	"TOKEN":       true,
	"SECRET":      true,
	"SECRETS":     true,
	"KEY":         true,
	"KEYS":        true,
	"PASSWORD":    true,
	"PASSWD":      true,
	"PASS":        true,
	"CREDENTIAL":  true,
	"CREDENTIALS": true,
	"CREDS":       true,
	"AUTH":        true,
	"APIKEY":      true,
	"PRIVATE":     true,
	"PAT":         true,
	"SIGNATURE":   true,
	"CERT":        true,
}

// knownSafe are variables whose names contain a secret-ish word but that carry
// no credential. Listing them explicitly is more honest than contorting the
// matcher until they happen to fall out.
var knownSafe = map[string]bool{
	"AWS_REGION":          true,
	"AWS_DEFAULT_REGION":  true,
	"AWS_PROFILE":         true,
	"AWS_DEFAULT_OUTPUT":  true,
	"AWS_PAGER":           true,
	"DOCKER_HOST":         true,
	"DOCKER_BUILDKIT":     true,
	"DOCKER_CONFIG":       true,
	"NPM_CONFIG_REGISTRY": true,
	"PYPI_INDEX_URL":      true,
	"GPG_TTY":             true,
	"SSH_AUTH_SOCK":       true,
	"SSH_CONNECTION":      true,
	"SSH_CLIENT":          true,
	"SSH_TTY":             true,
	"KEYCLOAK_URL":        true,
	"AUTHORITY":           true,
}

// LooksLikeSecret reports whether an environment variable name likely holds a
// credential, matching on whole words rather than substrings.
func LooksLikeSecret(key string) bool {
	upper := strings.ToUpper(key)
	if knownSafe[upper] {
		return false
	}

	for _, word := range splitWords(key) {
		if secretTokens[word] {
			return true
		}
	}
	return false
}

// splitWords breaks a variable name into uppercase word parts.
func splitWords(key string) []string {
	// Insert a boundary at lower-to-upper transitions so apiKey splits as
	// API + KEY, then split on every non-alphanumeric run.
	var b strings.Builder
	runes := []rune(key)
	for i, r := range runes {
		if i > 0 && r >= 'A' && r <= 'Z' && runes[i-1] >= 'a' && runes[i-1] <= 'z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}

	parts := strings.FieldsFunc(b.String(), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	for i := range parts {
		parts[i] = strings.ToUpper(parts[i])
	}
	return parts
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

// CompileSecretPatterns compiles forbidden-secret patterns, failing on the
// first one that will not compile.
//
// Compilation happens once, up front, for two reasons. It used to happen inside
// the match loop, recompiling every pattern for every candidate. Worse, a
// pattern that failed to compile was silently skipped — so a malformed rule in
// a platform profile meant the secret it was written to forbid was quietly
// allowed through. A security control that fails open on a typo is not a
// control, so a bad pattern is now a hard error the operator must fix.
func CompileSecretPatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid forbidden-secret pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// MatchSecrets returns the secret names matching any of the compiled patterns.
// Each name is reported at most once, however many patterns it matches.
func MatchSecrets(secrets []string, patterns []*regexp.Regexp) []string {
	var matched []string
	for _, s := range secrets {
		for _, re := range patterns {
			if re.MatchString(s) {
				matched = append(matched, s)
				break
			}
		}
	}
	return matched
}
