package main

import (
	"regexp"

	"github.com/data-insights-ai/rho-scg/platform"
	"github.com/data-insights-ai/rho-scg/scoper"
)

// compileForbidden compiles a profile's forbidden-secret patterns, preserving
// their order so a match can be reported against the rule that produced it.
//
// Both scope and audit previously compiled these inline, inside the match loop,
// and silently skipped any pattern that failed to compile. That is a security
// control failing open: a typo in a platform profile meant the forbidden secret
// was allowed through, and nothing said so.
func compileForbidden(specs []platform.ForbiddenSpec) ([]*regexp.Regexp, error) {
	patterns := make([]string, len(specs))
	for i, s := range specs {
		patterns[i] = s.Pattern
	}
	return scoper.CompileSecretPatterns(patterns)
}
