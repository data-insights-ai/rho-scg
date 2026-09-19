package scoper

import (
	"strings"
	"testing"
)

// The finding: an unparseable pattern was silently skipped, so the secret it
// was written to block sailed through. A least-privilege control must never
// fail open — a broken rule is a broken control, and the operator has to hear
// about it.
func TestCompileSecretPatterns_RejectsInvalidPattern(t *testing.T) {
	_, err := CompileSecretPatterns([]string{`^AWS_`, `([unclosed`})
	if err == nil {
		t.Fatal("an invalid forbidden-secret pattern must be a hard error, not a silent skip")
	}
	if !strings.Contains(err.Error(), "([unclosed") {
		t.Errorf("the error must name the offending pattern, got: %v", err)
	}
}

func TestMatchSecrets_MatchesCompiledPatterns(t *testing.T) {
	pats, err := CompileSecretPatterns([]string{`^AWS_`, `_TOKEN$`})
	if err != nil {
		t.Fatal(err)
	}

	got := MatchSecrets([]string{"AWS_SECRET_ACCESS_KEY", "NPM_TOKEN", "HOME"}, pats)
	if len(got) != 2 {
		t.Fatalf("matched %v, want AWS_SECRET_ACCESS_KEY and NPM_TOKEN", got)
	}
}

// A secret must be reported once even when several patterns match it,
// otherwise the same violation is counted repeatedly.
func TestMatchSecrets_NoDuplicates(t *testing.T) {
	pats, err := CompileSecretPatterns([]string{`^AWS_`, `_KEY$`, `SECRET`})
	if err != nil {
		t.Fatal(err)
	}
	got := MatchSecrets([]string{"AWS_SECRET_KEY"}, pats)
	if len(got) != 1 {
		t.Errorf("got %v, want exactly one entry", got)
	}
}

// Substring matching flagged ordinary variables as secrets. At that false
// positive rate an audit becomes noise people learn to skip.
func TestLooksLikeSecret_NoFalsePositives(t *testing.T) {
	notSecrets := []string{
		"MONKEY",      // contains KEY
		"KEYBOARD",    // contains KEY
		"DONKEY",      // contains KEY
		"AUTHOR",      // contains AUTH
		"AUTHORITY",   // contains AUTH
		"AWS_REGION",  // AWS, but a region is not a credential
		"AWS_PROFILE", // ditto
		"DOCKER_HOST", // a host, not a credential
		"DOCKER_BUILDKIT",
		"NPM_CONFIG_REGISTRY",
		"KEYCLOAK_URL",
		"HOME",
		"PATH",
	}
	for _, k := range notSecrets {
		if LooksLikeSecret(k) {
			t.Errorf("LooksLikeSecret(%q) = true, want false", k)
		}
	}
}

// The genuine article must still be caught. A tightened matcher that misses
// real secrets is worse than the noisy one it replaced.
func TestLooksLikeSecret_CatchesRealSecrets(t *testing.T) {
	secrets := []string{
		"GITHUB_TOKEN",
		"NPM_TOKEN",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_ACCESS_KEY_ID",
		"DOCKER_PASSWORD",
		"PYPI_API_TOKEN",
		"SSH_PRIVATE_KEY",
		"GPG_PRIVATE_KEY",
		"DATABASE_PASSWORD",
		"STRIPE_SECRET_KEY",
		"api_key",
		"AZURE_CLIENT_SECRET",
		"GCP_CREDENTIALS",
		"MY_APP_CREDENTIAL",
	}
	for _, k := range secrets {
		if !LooksLikeSecret(k) {
			t.Errorf("LooksLikeSecret(%q) = false, want true", k)
		}
	}
}
