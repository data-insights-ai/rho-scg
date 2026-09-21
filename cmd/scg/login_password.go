package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/data-insights-ai/rho-scg/internal/config"
	"golang.org/x/term"
)

// The device flow needs a person at a browser: it prints a code, somebody
// approves it, the CLI collects a key. That is right for a laptop and
// impossible for everything else. An agent setting a project up, a CI
// image being built, a container with no browser and no mailbox cannot
// approve anything, and cannot read a mailed link either.
//
// scg login --password is the way in for those. It signs in with an
// address and a password, mints one API key with the session it gets
// back, and stores that key exactly where the device flow stores its own.
// From then on nothing else differs: the password is not kept anywhere,
// and the key is what the machine uses.

// passwordEnv is where a non-interactive caller puts the password. A flag
// would land in the shell history and in every process listing on the
// machine; an environment variable does not.
const passwordEnv = "SCG_PASSWORD"

// loginWithPassword signs in with an address and password and stores the
// key it mints. It never writes the password anywhere, including errors.
func loginWithPassword(ctx context.Context, client *http.Client, base, email, password string, out io.Writer) error {
	if email == "" {
		return errors.New("scg login --password needs an address: pass --email you@company.com")
	}
	if password == "" {
		return fmt.Errorf("no password given: set %s, or run without --password to sign in through the browser", passwordEnv)
	}

	var session struct {
		Organization string `json:"organization"`
		SessionToken string `json:"session_token"`
	}
	err := postJSON(ctx, client, base+"/v1/login/password",
		map[string]string{"email": email, "password": password}, &session)
	var failed *httpError
	switch {
	case errors.As(err, &failed) && failed.status == http.StatusUnauthorized:
		return errors.New("that address and password do not match an account.\n" +
			"If you never set a password, open your account page, go to Password and set one;\n" +
			"or run scg login without --password to sign in through the browser instead")
	case errors.As(err, &failed) && failed.status == http.StatusTooManyRequests:
		return errors.New("too many failed attempts for this address; it is shut for fifteen minutes")
	case err != nil:
		return fmt.Errorf("sign-in failed: %w", err)
	}
	if session.SessionToken == "" {
		return errors.New("the platform accepted the password but returned no session")
	}

	// The session is a means, not the credential: it buys one API key and
	// is then dropped. The key is what this machine keeps.
	var got struct {
		Organization string `json:"organization"`
		Key          struct {
			Token  string `json:"token"`
			Prefix string `json:"prefix"`
		} `json:"key"`
	}
	if err := postSession(ctx, client, base+"/v1/keys", session.SessionToken, &got); err != nil {
		return fmt.Errorf("signed in, but no key could be created: %w", err)
	}
	if got.Key.Token == "" {
		return errors.New("signed in, but the platform returned no key")
	}
	org := got.Organization
	if org == "" {
		org = session.Organization
	}

	path, err := config.SaveCredentials(config.Credentials{
		APIKey: got.Key.Token, Organization: org, PlatformURL: base,
		KeyPrefix: got.Key.Prefix, SavedAt: time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("signed in, but the key could not be stored: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Signed in to %s. Key %s… stored in %s (owner-only).\n", org, got.Key.Prefix, path)
	_, _ = fmt.Fprintln(out, "The password is not stored; the key is. Revoke it in your account page if this machine is lost.")
	return nil
}

// postSession posts with a session token in the header rather than a key.
func postSession(ctx context.Context, client *http.Client, url, session string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Session-Token", session)
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

// readPassword takes the password from the environment when there is one,
// and otherwise asks for it without echoing. When input is piped it reads
// one line, which is what a script that pipes a secret expects.
func readPassword(in *os.File, out io.Writer) (string, error) {
	if v := os.Getenv(passwordEnv); v != "" {
		return v, nil
	}
	if term.IsTerminal(int(in.Fd())) {
		_, _ = fmt.Fprint(out, "Password: ")
		raw, err := term.ReadPassword(int(in.Fd()))
		_, _ = fmt.Fprintln(out)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
