// Package dsm implements the Dependency Security Model — security profiles
// for CI/CD tools that define what secrets each tool legitimately needs.
package dsm

import (
	"context"
	"fmt"

	scggraph "gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/graph"
	tkgraph "gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/graph"
	"gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/types"
)

// RiskTier classifies the risk level of a CI/CD tool.
const (
	TierLow      = 0 // read-only, no secrets needed
	TierMedium   = 1 // needs some secrets (e.g. private registry auth)
	TierHigh     = 2 // runs with broad secret access
	TierCritical = 3 // publishes artifacts (pypi, npm, docker)
)

// ProfileDef defines a security profile for a CI/CD tool.
type ProfileDef struct {
	Ecosystem         string
	Reference         string
	Owner             string
	Name              string
	RiskTier          int
	RequiredSecrets   []SecretRequirement
	ForbiddenPatterns []PatternDef
}

// SecretRequirement defines a secret a tool legitimately needs.
type SecretRequirement struct {
	Name        string
	Permissions string
	Required    bool
}

// PatternDef defines a forbidden secret pattern.
type PatternDef struct {
	Regex  string
	Reason string
}

// EmbeddedProfiles contains bootstrap security profiles for the most common
// GitHub Actions. These are the foundation — the platform extends this with
// thousands of community-curated profiles.
var EmbeddedProfiles = []ProfileDef{
	{
		Ecosystem: "github_action",
		Reference: "actions/checkout",
		Owner:     "actions",
		Name:      "checkout",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/setup-node",
		Owner:     "actions",
		Name:      "setup-node",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/setup-python",
		Owner:     "actions",
		Name:      "setup-python",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/setup-go",
		Owner:     "actions",
		Name:      "setup-go",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/cache",
		Owner:     "actions",
		Name:      "cache",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/upload-artifact",
		Owner:     "actions",
		Name:      "upload-artifact",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "actions:write", Required: true},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/download-artifact",
		Owner:     "actions",
		Name:      "download-artifact",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "actions:read", Required: true},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "aquasecurity/trivy-action",
		Owner:     "aquasecurity",
		Name:      "trivy-action",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "read:packages", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "Trivy does not publish to PyPI"},
			{Regex: `NPM_TOKEN`, Reason: "Trivy does not publish to npm"},
			{Regex: `DOCKER_HUB_PASSWORD`, Reason: "Trivy reads images, does not push"},
			{Regex: `AWS_SECRET_ACCESS_KEY`, Reason: "Trivy scans locally, no cloud write needed"},
			{Regex: `SSH_PRIVATE_KEY`, Reason: "Trivy does not need SSH access"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "docker/build-push-action",
		Owner:     "docker",
		Name:      "build-push-action",
		RiskTier:  TierCritical,
		RequiredSecrets: []SecretRequirement{
			{Name: "DOCKER_HUB_TOKEN", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "Docker push does not need PyPI credentials"},
			{Regex: `NPM_TOKEN`, Reason: "Docker push does not need npm credentials"},
			{Regex: `AWS_SECRET_ACCESS_KEY`, Reason: "Docker push does not need AWS credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "pypa/gh-action-pypi-publish",
		Owner:     "pypa",
		Name:      "gh-action-pypi-publish",
		RiskTier:  TierCritical,
		RequiredSecrets: []SecretRequirement{
			{Name: "PYPI_API_TOKEN", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `AWS_SECRET.*`, Reason: "PyPI publish does not need cloud credentials"},
			{Regex: `DOCKER_HUB.*`, Reason: "PyPI publish does not need Docker access"},
			{Regex: `SSH_PRIVATE_KEY`, Reason: "PyPI publish does not need SSH access"},
		},
	},
}

// Bootstrap populates the graph with embedded security profiles.
// This creates Tool, Profile, Secret, and SecretPattern nodes along with
// their relationships. Uses a transaction for atomicity.
func Bootstrap(ctx context.Context, g *tkgraph.Graph) error {
	tx := g.BeginTx()
	defer tx.Rollback()

	for _, pd := range EmbeddedProfiles {
		// Create or find the Tool node.
		toolNode, err := tx.AddNode(
			[]string{scggraph.LabelTool},
			map[string]any{
				"ecosystem": pd.Ecosystem,
				"reference": pd.Reference,
				"owner":     pd.Owner,
				"name":      pd.Name,
			},
		)
		if err != nil {
			return fmt.Errorf("create tool %s: %w", pd.Reference, err)
		}

		// Create the Profile node.
		profileNode, err := tx.AddNode(
			[]string{scggraph.LabelProfile},
			map[string]any{
				"risk_tier":  pd.RiskTier,
				"version":    "embedded-v1",
				"audited_by": "scg-core",
			},
		)
		if err != nil {
			return fmt.Errorf("create profile for %s: %w", pd.Reference, err)
		}

		// Link Tool → Profile.
		_, err = tx.AddRelationship(
			scggraph.RelHasProfile,
			toolNode, profileNode,
			nil,
		)
		if err != nil {
			return fmt.Errorf("link tool→profile for %s: %w", pd.Reference, err)
		}

		// Create required secret nodes and REQUIRES relationships.
		for _, req := range pd.RequiredSecrets {
			secretNode, err := tx.AddNode(
				[]string{scggraph.LabelSecret},
				map[string]any{
					"name":     req.Name,
					"source":   "profile",
					"category": "required",
				},
			)
			if err != nil {
				return fmt.Errorf("create secret %s for %s: %w", req.Name, pd.Reference, err)
			}

			_, err = tx.AddRelationship(
				scggraph.RelRequires,
				profileNode, secretNode,
				map[string]any{
					"permissions": req.Permissions,
					"required":    req.Required,
				},
			)
			if err != nil {
				return fmt.Errorf("link profile→secret for %s: %w", pd.Reference, err)
			}
		}

		// Create forbidden pattern nodes and FORBIDS relationships.
		for _, pat := range pd.ForbiddenPatterns {
			patternNode, err := tx.AddNode(
				[]string{scggraph.LabelSecretPattern},
				map[string]any{
					"regex":  pat.Regex,
					"reason": pat.Reason,
				},
			)
			if err != nil {
				return fmt.Errorf("create pattern %s for %s: %w", pat.Regex, pd.Reference, err)
			}

			_, err = tx.AddRelationship(
				scggraph.RelForbids,
				profileNode, patternNode,
				nil,
			)
			if err != nil {
				return fmt.Errorf("link profile→pattern for %s: %w", pd.Reference, err)
			}
		}
	}

	return tx.Commit()
}

// toolID extracts the Snowflake ID from a node for use in relationship creation.
func toolID(n *types.Node) int64 {
	return n.InternalID().SnowflakeID().Int64()
}
