package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// maxResponseBytes is the maximum HTTP response body size (10MB).
// Prevents OOM from malicious registries returning oversized responses.
const maxResponseBytes = 10 * 1024 * 1024

// decodeJSON reads a limited-size JSON response body into dst.
func decodeJSON(resp *http.Response, dst any) error {
	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(lr).Decode(dst); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// escapePath safely encodes a string for use in a URL path segment.
func escapePath(s string) string {
	return url.PathEscape(s)
}
