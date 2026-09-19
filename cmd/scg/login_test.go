package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/data-insights-ai/rho-scg/internal/config"
)

// devicePlatform fakes the platform's device flow: the first n polls are
// pending, then a key is handed out once.
func devicePlatform(t *testing.T, pendingPolls int, finalStatus int) *httptest.Server {
	t.Helper()
	polls := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dev-1", "user_code": "ABCD-1234",
				"verification_url": "https://scg.example.test/account?device=ABCD-1234", "interval": 1,
			})
		case "/v1/device/token":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["device_code"] != "dev-1" {
				http.Error(w, `{"error":"unknown code"}`, http.StatusNotFound)
				return
			}
			polls++
			if polls <= pendingPolls {
				http.Error(w, `{"error":"pending"}`, http.StatusPreconditionRequired)
				return
			}
			if finalStatus != http.StatusOK {
				http.Error(w, `{"error":"expired"}`, finalStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"organization": "acme", "key": map[string]string{"token": "scg_test_key", "prefix": "scg_test"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestLogin_StoresTheKeyAfterApproval(t *testing.T) {
	t.Setenv("SCG_CONFIG_DIR", t.TempDir())
	pollUnit = time.Millisecond
	t.Cleanup(func() { pollUnit = time.Second })
	srv := devicePlatform(t, 2, http.StatusOK)
	defer srv.Close()

	var out bytes.Buffer
	if err := login(context.Background(), srv.Client(), srv.URL, true, &out); err != nil {
		t.Fatalf("login: %v\n%s", err, out.String())
	}
	for _, want := range []string{"ABCD-1234", "Signed in to acme", "scg_test…"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	creds, err := config.LoadCredentials()
	if err != nil || creds.APIKey != "scg_test_key" || creds.PlatformURL != srv.URL || creds.Organization != "acme" {
		t.Fatalf("stored credentials = %+v, %v", creds, err)
	}

	// Logout forgets it and says the key keeps working.
	var logoutOut bytes.Buffer
	if err := logout(&logoutOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logoutOut.String(), "Forgot the key scg_test…") {
		t.Errorf("logout output: %s", logoutOut.String())
	}
	if creds, _ := config.LoadCredentials(); creds.APIKey != "" {
		t.Fatal("credentials still present after logout")
	}
	logoutOut.Reset()
	if err := logout(&logoutOut); err != nil || !strings.Contains(logoutOut.String(), "Nothing was stored") {
		t.Errorf("second logout: %v %s", err, logoutOut.String())
	}
}

func TestLogin_ExpiredCodeIsReported(t *testing.T) {
	t.Setenv("SCG_CONFIG_DIR", t.TempDir())
	pollUnit = time.Millisecond
	t.Cleanup(func() { pollUnit = time.Second })
	srv := devicePlatform(t, 0, http.StatusGone)
	defer srv.Close()
	err := login(context.Background(), srv.Client(), srv.URL, true, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want expiry error, got %v", err)
	}
	if creds, _ := config.LoadCredentials(); creds.APIKey != "" {
		t.Fatal("no key must be stored")
	}
}

func TestLogin_UnreachablePlatformAndCancel(t *testing.T) {
	t.Setenv("SCG_CONFIG_DIR", t.TempDir())
	srv := devicePlatform(t, 100, http.StatusOK)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := login(ctx, srv.Client(), srv.URL, true, &bytes.Buffer{}); err == nil {
		t.Fatal("cancelled context must end the wait")
	}
	closed := devicePlatform(t, 0, http.StatusOK)
	closed.Close()
	if err := login(context.Background(), &http.Client{Timeout: time.Second}, closed.URL, true, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "could not start") {
		t.Fatalf("want start error, got %v", err)
	}
}

func TestRunLogin_RefusesPlainHTTPOverTheNetwork(t *testing.T) {
	t.Setenv("SCG_PLATFORM_URL", "http://scg.example.test")
	if err := runLogin(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("want https refusal, got %v", err)
	}
	if err := runLogin(context.Background(), []string{"--bogus"}); err == nil {
		t.Fatal("unknown flag must fail")
	}
	for base, ok := range map[string]bool{"https://scg.example.test": true, "http://localhost:8080": true, "http://127.0.0.1:1": true, "http://scg.example.test": false, "ftp://x": false, "::bad": false} {
		if got := secureBaseURL(base); got != ok {
			t.Errorf("secureBaseURL(%q) = %v", base, got)
		}
	}
}

func TestHTTPError_Message(t *testing.T) {
	if got := (&httpError{status: 500}).Error(); got != "HTTP 500" {
		t.Error(got)
	}
	if got := (&httpError{status: 404, body: "nope"}).Error(); got != "HTTP 404: nope" {
		t.Error(got)
	}
}
