package repo

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"https://github.com/Acme/App.git":     "github.com/acme/app",
		"git@github.com:acme/app.git":         "github.com/acme/app",
		"ssh://git@github.com/acme/app":       "github.com/acme/app",
		"github.com/acme/app/":                "github.com/acme/app",
		"https://gitlab.example.com:8443/g/p": "gitlab.example.com/g/p",
		"  GitHub.com/acme/app  ":             "github.com/acme/app",
	}
	for in, want := range cases {
		if got, err := Normalize(in); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "acme", "has space/x", "/lead/x", "über/x"} {
		if _, err := Normalize(bad); !errors.Is(err, ErrUnknown) {
			t.Errorf("Normalize(%q) accepted", bad)
		}
	}
}

func TestDetectPrecedence(t *testing.T) {
	for _, k := range []string{"SCG_REPO", "GITHUB_REPOSITORY", "GITHUB_SERVER_URL", "CI_PROJECT_URL"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	if _, err := Detect(dir, ""); !errors.Is(err, ErrUnknown) {
		t.Fatalf("nothing to go on: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:acme/from-git.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := Detect(sub, ""); err != nil || got != "github.com/acme/from-git" {
		t.Fatalf("git config: %q %v", got, err)
	}
	t.Setenv("CI_PROJECT_URL", "https://gitlab.com/acme/from-gitlab")
	if got, _ := Detect(sub, ""); got != "gitlab.com/acme/from-gitlab" {
		t.Fatalf("gitlab: %q", got)
	}
	t.Setenv("GITHUB_REPOSITORY", "Acme/From-Actions")
	if got, _ := Detect(sub, ""); got != "github.com/acme/from-actions" {
		t.Fatalf("actions: %q", got)
	}
	t.Setenv("GITHUB_SERVER_URL", "https://ghe.example.com")
	if got, _ := Detect(sub, ""); got != "ghe.example.com/acme/from-actions" {
		t.Fatalf("enterprise server: %q", got)
	}
	t.Setenv("SCG_REPO", "github.com/acme/from-env")
	if got, _ := Detect(sub, ""); got != "github.com/acme/from-env" {
		t.Fatalf("env: %q", got)
	}
	if got, _ := Detect(sub, "github.com/acme/from-flag"); got != "github.com/acme/from-flag" {
		t.Fatalf("flag: %q", got)
	}
	if _, err := Detect(sub, "not a repo"); err == nil {
		t.Fatal("bad flag")
	}
}
