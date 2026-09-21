package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/data-insights-ai/rho-scg/internal/config"
)

// passwordPlatform fakes the two calls the password sign-in makes, and
// insists on the header rather than a cookie: that is the whole point of
// the path, so the test would be worthless without checking it.
func passwordPlatform(t *testing.T, password string, signInStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/login/password":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if signInStatus != http.StatusOK {
				w.WriteHeader(signInStatus)
				_, _ = w.Write([]byte(`{"error":"email or password is wrong"}`))
				return
			}
			if body["email"] != "alice@example.com" || body["password"] != password {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"email or password is wrong"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"organization": "acme", "session_token": "sess-1",
			})
		case "/v1/keys":
			if r.Header.Get("X-Session-Token") != "sess-1" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"not signed in"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"organization": "acme",
				"key":          map[string]any{"token": "scg_live_secret", "prefix": "scg_abcd"},
			})
		default:
			http.Error(w, `{"error":"no"}`, http.StatusNotFound)
		}
	}))
}

func TestLoginWithPassword_StoresTheKeyItMints(t *testing.T) {
	t.Setenv("SCG_CONFIG_DIR", t.TempDir())
	srv := passwordPlatform(t, "correct horse battery staple", http.StatusOK)
	defer srv.Close()

	var out bytes.Buffer
	err := loginWithPassword(context.Background(), srv.Client(), srv.URL,
		"alice@example.com", "correct horse battery staple", &out)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := config.LoadCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if creds.APIKey != "scg_live_secret" || creds.Organization != "acme" {
		t.Fatalf("stored %+v", creds)
	}
	if !strings.Contains(out.String(), "Signed in to acme") {
		t.Fatalf("output was %q", out.String())
	}
	// The password must not turn up anywhere the machine keeps or prints.
	if strings.Contains(out.String(), "correct horse") {
		t.Fatal("the password was printed")
	}
	raw, _ := json.Marshal(creds)
	if strings.Contains(string(raw), "correct horse") {
		t.Fatal("the password was stored")
	}
}

func TestLoginWithPassword_SaysWhatToDoWhenItFails(t *testing.T) {
	t.Setenv("SCG_CONFIG_DIR", t.TempDir())

	cases := []struct {
		name, email, password string
		status                int
		want                  string
	}{
		{name: "no address", password: "x", status: http.StatusOK, want: "--email"},
		{name: "no password", email: "alice@example.com", status: http.StatusOK, want: "SCG_PASSWORD"},
		{name: "wrong password", email: "alice@example.com", password: "nope nope nope", status: http.StatusUnauthorized, want: "set one"},
		{name: "locked out", email: "alice@example.com", password: "nope nope nope", status: http.StatusTooManyRequests, want: "fifteen minutes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := passwordPlatform(t, "correct horse battery staple", c.status)
			defer srv.Close()
			var out bytes.Buffer
			err := loginWithPassword(context.Background(), srv.Client(), srv.URL, c.email, c.password, &out)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
			if creds, _ := config.LoadCredentials(); creds.APIKey != "" {
				t.Fatalf("a failed sign-in stored %q", creds.KeyPrefix)
			}
		})
	}
}

// A script pipes the password in; that must work without a terminal.
func TestReadPassword_TakesTheEnvironmentThenStandardInput(t *testing.T) {
	t.Setenv(passwordEnv, "from the environment")
	var out bytes.Buffer
	got, err := readPassword(nil, &out)
	if err != nil || got != "from the environment" {
		t.Fatalf("got %q, err %v", got, err)
	}

	t.Setenv(passwordEnv, "")
	f, err := writeTempFile(t, "piped in\n")
	if err != nil {
		t.Fatal(err)
	}
	got, err = readPassword(f, &out)
	if err != nil || got != "piped in" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func writeTempFile(t *testing.T, content string) (*os.File, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, nil
}
