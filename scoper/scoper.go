// Package scoper implements the secret scoping policy engine.
// It evaluates which secrets a CI/CD step should have access to
// by querying the graph for forbidden patterns from tool profiles.
package scoper

import (
	"context"
	"fmt"

	scggraph "gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/graph"
	"gitlab2024.bds421-cloud.com/bds421/sigma/tkgd/pkg/cypher"
)

// Violation represents a secret that a step has access to but shouldn't.
type Violation struct {
	Secret  string
	Pattern string
	Reason  string
	Tool    string
	Action  string // "blocked" or "warning"
}

// ScopeResult is the outcome of scoping a step's secret access.
type ScopeResult struct {
	StepName   string
	Violations []Violation
	Warnings   []string
	RiskTier   int
}

// Scope evaluates secret access policy for a step using graph queries.
// It finds all secrets the step has access to that are forbidden by
// the tool's security profile.
func Scope(ctx context.Context, engine *cypher.Engine, stepName string) (*ScopeResult, error) {
	result := &ScopeResult{StepName: stepName}

	// Query for secret violations.
	qr, err := engine.Execute(ctx, scggraph.QuerySecretViolations, map[string]any{
		"step": stepName,
	})
	if err != nil {
		return nil, fmt.Errorf("query secret violations: %w", err)
	}

	for _, row := range qr.Rows {
		v := Violation{
			Action: "blocked",
		}
		if s, ok := row["secret"].(string); ok {
			v.Secret = s
		}
		if p, ok := row["pattern"].(string); ok {
			v.Pattern = p
		}
		if r, ok := row["reason"].(string); ok {
			v.Reason = r
		}
		if t, ok := row["tool"].(string); ok {
			v.Tool = t
		}
		if rt, ok := row["risk_tier"].(int64); ok {
			result.RiskTier = int(rt)
		}
		result.Violations = append(result.Violations, v)
	}

	return result, nil
}
