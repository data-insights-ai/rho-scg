package scoper

import "testing"

func TestLooksLikeSecret(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"GITHUB_TOKEN", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"PYPI_API_TOKEN", true},
		{"NPM_TOKEN", true},
		{"DOCKER_HUB_PASSWORD", true},
		{"SSH_PRIVATE_KEY", true},
		{"MY_API_KEY", true},
		{"GCP_CREDENTIAL", true},
		{"PATH", false},
		{"HOME", false},
		{"GOPATH", false},
		{"SHELL", false},
		{"CI", false},
		{"RUNNER_OS", false},
	}

	for _, tt := range tests {
		if got := LooksLikeSecret(tt.key); got != tt.want {
			t.Errorf("LooksLikeSecret(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestMatchSecrets(t *testing.T) {
	secrets := []string{"PYPI_API_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_KEY", "NPM_TOKEN"}
	patterns := []string{`PYPI.*`, `AWS_SECRET.*`}

	matched := MatchSecrets(secrets, patterns)
	if len(matched) != 2 {
		t.Fatalf("matched = %d, want 2", len(matched))
	}

	want := map[string]bool{"PYPI_API_TOKEN": true, "AWS_SECRET_KEY": true}
	for _, m := range matched {
		if !want[m] {
			t.Errorf("unexpected match: %q", m)
		}
	}
}

func TestMatchSecrets_InvalidRegex(t *testing.T) {
	secrets := []string{"FOO_TOKEN"}
	patterns := []string{"[invalid"} // bad regex

	// Should not panic, just skip invalid patterns.
	matched := MatchSecrets(secrets, patterns)
	if len(matched) != 0 {
		t.Errorf("expected no matches for invalid regex, got %d", len(matched))
	}
}

func TestMatchSecrets_Empty(t *testing.T) {
	matched := MatchSecrets(nil, nil)
	if len(matched) != 0 {
		t.Errorf("expected no matches, got %d", len(matched))
	}
}
