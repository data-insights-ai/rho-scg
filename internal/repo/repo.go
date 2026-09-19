// Package repo names the repository a lockfile belongs to, the identity the
// platform keys watches by ("github.com/owner/name").
package repo

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrUnknown reports that no repository could be determined.
var ErrUnknown = errors.New("could not determine the repository; pass --repo github.com/owner/name")

// Detect returns the repository name for dir, from the first of: the flag
// value, SCG_REPO, GITHUB_REPOSITORY (GitHub Actions), CI_PROJECT_URL
// (GitLab), the origin remote in .git/config (walking up from dir).
func Detect(dir, flag string) (string, error) {
	if v := strings.TrimSpace(flag); v != "" {
		return Normalize(v)
	}
	if v := os.Getenv("SCG_REPO"); v != "" {
		return Normalize(v)
	}
	if v := os.Getenv("GITHUB_REPOSITORY"); v != "" {
		host := os.Getenv("GITHUB_SERVER_URL")
		if host == "" {
			host = "https://github.com"
		}
		return Normalize(strings.TrimRight(host, "/") + "/" + v)
	}
	if v := os.Getenv("CI_PROJECT_URL"); v != "" {
		return Normalize(v)
	}
	if v := originFromGitConfig(dir); v != "" {
		return Normalize(v)
	}
	return "", ErrUnknown
}

var repoName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9._-]+)+$`)

// Normalize canonicalises a repository name or URL: lower case, no scheme,
// no user, no trailing .git or slash; "host/owner/name".
func Normalize(raw string) (string, error) {
	r := strings.TrimSpace(strings.ToLower(raw))
	for _, p := range []string{"https://", "http://", "ssh://", "git://"} {
		r = strings.TrimPrefix(r, p)
	}
	if i := strings.Index(r, "@"); i >= 0 && !strings.Contains(r[:i], "/") {
		r = r[i+1:] // git@github.com:owner/name
	}
	if i := strings.Index(r, ":"); i >= 0 && !strings.Contains(r[:i], "/") {
		// host:owner/name (scp-like) or host:port/owner/name; drop a port.
		rest := r[i+1:]
		if j := strings.Index(rest, "/"); j >= 0 && isDigits(rest[:j]) {
			r = r[:i] + rest[j:]
		} else {
			r = r[:i] + "/" + rest
		}
	}
	r = strings.TrimSuffix(strings.TrimSuffix(r, "/"), ".git")
	if len(r) > 200 || !repoName.MatchString(r) {
		return "", ErrUnknown
	}
	return r, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// originFromGitConfig reads [remote "origin"] url from the nearest
// .git/config above dir, without running git.
func originFromGitConfig(dir string) string {
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		cfg := filepath.Join(abs, ".git", "config")
		if raw, err := os.ReadFile(cfg); err == nil {
			return originURL(string(raw))
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return ""
		}
		abs = parent
	}
}

func originURL(config string) string {
	inOrigin := false
	for _, line := range strings.Split(config, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			inOrigin = t == `[remote "origin"]`
			continue
		}
		if inOrigin && strings.HasPrefix(t, "url") {
			if _, v, ok := strings.Cut(t, "="); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}
