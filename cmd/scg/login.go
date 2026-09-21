package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/data-insights-ai/rho-scg/internal/config"
)

// runLogin signs this machine in without anyone copying a key: the platform
// hands out a short code, the person approves it in the browser, and the
// CLI collects a key of that organization once. The key is stored in the
// user's config directory with owner-only permissions.
func runLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	noBrowser := fs.Bool("no-browser", false, "print the link instead of opening the browser")
	withPassword := fs.Bool("password", false, "sign in with an address and password instead of the browser")
	email := fs.String("email", "", "the address to sign in with (only with --password)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := config.Load()
	if !secureBaseURL(cfg.PlatformBaseURL) {
		return fmt.Errorf("refusing to sign in over %s: use https", cfg.PlatformBaseURL)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if *withPassword {
		// Deliberately no --password=value: a flag lands in the shell
		// history and in every process listing on the machine.
		password, err := readPassword(os.Stdin, os.Stdout)
		if err != nil {
			return fmt.Errorf("could not read the password: %w", err)
		}
		return loginWithPassword(ctx, client, cfg.PlatformBaseURL, strings.TrimSpace(*email), password, os.Stdout)
	}
	if *email != "" {
		return errors.New("--email only applies to scg login --password")
	}
	return login(ctx, client, cfg.PlatformBaseURL, *noBrowser, os.Stdout)
}

// secureBaseURL allows https everywhere and plain http only on this machine
// (a local platform in development), never a key over the network in clear.
func secureBaseURL(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// login runs the device flow against base and stores the key it yields.
func login(ctx context.Context, client *http.Client, base string, noBrowser bool, out io.Writer) error {

	var start struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
		ExpiresAt       string `json:"expires_at"`
		Interval        int    `json:"interval"`
	}
	if err := postJSON(ctx, client, base+"/v1/device", nil, &start); err != nil {
		return fmt.Errorf("could not start the sign-in: %w", err)
	}
	if start.Interval < 1 {
		start.Interval = 5
	}

	_, _ = fmt.Fprintf(out, "Sign in to SCG\n\n  Code:  %s\n  Open:  %s\n\n", start.UserCode, start.VerificationURL)
	if !noBrowser && openBrowser(ctx, start.VerificationURL) {
		_, _ = fmt.Fprintln(out, "Your browser is opening the page. Approve the code there, then come back here.")
	} else {
		_, _ = fmt.Fprintln(out, "Open the link in a browser, sign in to your organization and approve the code.")
	}
	_, _ = fmt.Fprintln(out, "Waiting…")

	ticker := time.NewTicker(time.Duration(start.Interval) * pollUnit)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		var got struct {
			Organization string `json:"organization"`
			Key          struct {
				Token  string `json:"token"`
				Prefix string `json:"prefix"`
			} `json:"key"`
		}
		err := postJSON(ctx, client, base+"/v1/device/token", map[string]string{"device_code": start.DeviceCode}, &got)
		var pending *httpError
		switch {
		case errors.As(err, &pending) && pending.status == 428:
			continue
		case errors.As(err, &pending) && pending.status == 410:
			return errors.New("the code expired before it was approved; run scg login again")
		case err != nil:
			return fmt.Errorf("sign-in failed: %w", err)
		}
		path, err := config.SaveCredentials(config.Credentials{
			APIKey: got.Key.Token, Organization: got.Organization, PlatformURL: base,
			KeyPrefix: got.Key.Prefix, SavedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("signed in, but the key could not be stored: %w", err)
		}
		_, _ = fmt.Fprintf(out, "\nSigned in to %s. Key %s… stored in %s (owner-only).\n", got.Organization, got.Key.Prefix, path)
		_, _ = fmt.Fprintln(out, "scg uses it from now on; SCG_API_KEY in the environment still takes precedence, so CI is unchanged.")
		return nil
	}
}

// runLogout forgets the stored key. The key itself keeps working until it
// is revoked in the organization page; say so.
func runLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return logout(os.Stdout)
}

func logout(out io.Writer) error {
	creds, _ := config.LoadCredentials()
	path, err := config.RemoveCredentials()
	if err != nil {
		return err
	}
	if creds.APIKey == "" {
		_, _ = fmt.Fprintln(out, "Nothing was stored.")
		return nil
	}
	_, _ = fmt.Fprintf(out, "Forgot the key %s… for %s (%s removed).\n", creds.KeyPrefix, creds.Organization, path)
	_, _ = fmt.Fprintln(out, "The key itself keeps working until you revoke it in your organization page.")
	return nil
}

// pollUnit scales the server's poll interval; tests shrink it.
var pollUnit = time.Second

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string {
	if e.body != "" {
		return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
	}
	return fmt.Sprintf("HTTP %d", e.status)
}

// postJSON sends a JSON body (nil for none) and decodes a JSON response;
// non-2xx statuses become *httpError with the server's message.
func postJSON(ctx context.Context, client *http.Client, url string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "scg/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var msg struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &msg)
		return &httpError{status: resp.StatusCode, body: msg.Error}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// openBrowser tries the platform's opener; false when it could not.
func openBrowser(ctx context.Context, url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", url)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false
		}
		cmd = exec.CommandContext(ctx, "xdg-open", url)
	}
	return cmd.Start() == nil
}
