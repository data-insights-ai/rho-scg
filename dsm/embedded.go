// Package dsm implements the Dependency Security Model — security profiles
// for CI/CD tools that define what secrets each tool legitimately needs.
package dsm

import (
	"context"
	"fmt"
	"regexp"

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
	// --- Additional profiles (11-30) ---
	{
		Ecosystem: "github_action",
		Reference: "actions/setup-java",
		Owner:     "actions",
		Name:      "setup-java",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/setup-dotnet",
		Owner:     "actions",
		Name:      "setup-dotnet",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/github-script",
		Owner:     "actions",
		Name:      "github-script",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "varies", Required: true},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/create-release",
		Owner:     "actions",
		Name:      "create-release",
		RiskTier:  TierHigh,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "contents:write", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "Release creation does not need PyPI credentials"},
			{Regex: `NPM_TOKEN`, Reason: "Release creation does not need npm credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "actions/deploy-pages",
		Owner:     "actions",
		Name:      "deploy-pages",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "pages:write", Required: true},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "aws-actions/configure-aws-credentials",
		Owner:     "aws-actions",
		Name:      "configure-aws-credentials",
		RiskTier:  TierHigh,
		RequiredSecrets: []SecretRequirement{
			{Name: "AWS_ACCESS_KEY_ID", Required: true},
			{Name: "AWS_SECRET_ACCESS_KEY", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "AWS auth does not need PyPI credentials"},
			{Regex: `NPM_TOKEN`, Reason: "AWS auth does not need npm credentials"},
			{Regex: `DOCKER_HUB.*`, Reason: "AWS auth does not need Docker Hub credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "google-github-actions/auth",
		Owner:     "google-github-actions",
		Name:      "auth",
		RiskTier:  TierHigh,
		RequiredSecrets: []SecretRequirement{
			{Name: "GCP_CREDENTIALS", Required: false},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "GCP auth does not need PyPI credentials"},
			{Regex: `NPM_TOKEN`, Reason: "GCP auth does not need npm credentials"},
			{Regex: `AWS_SECRET.*`, Reason: "GCP auth does not need AWS credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "azure/login",
		Owner:     "azure",
		Name:      "login",
		RiskTier:  TierHigh,
		RequiredSecrets: []SecretRequirement{
			{Name: "AZURE_CREDENTIALS", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "Azure auth does not need PyPI credentials"},
			{Regex: `AWS_SECRET.*`, Reason: "Azure auth does not need AWS credentials"},
			{Regex: `GCP_CREDENTIALS`, Reason: "Azure auth does not need GCP credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "docker/login-action",
		Owner:     "docker",
		Name:      "login-action",
		RiskTier:  TierHigh,
		RequiredSecrets: []SecretRequirement{
			{Name: "DOCKER_HUB_TOKEN", Required: false},
			{Name: "GITHUB_TOKEN", Permissions: "packages:write", Required: false},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "docker/setup-buildx-action",
		Owner:     "docker",
		Name:      "setup-buildx-action",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "docker/metadata-action",
		Owner:     "docker",
		Name:      "metadata-action",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "github/codeql-action",
		Owner:     "github",
		Name:      "codeql-action",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "security-events:write", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "CodeQL does not publish packages"},
			{Regex: `NPM_TOKEN`, Reason: "CodeQL does not publish packages"},
			{Regex: `AWS_SECRET.*`, Reason: "CodeQL does not need cloud credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "codecov/codecov-action",
		Owner:     "codecov",
		Name:      "codecov-action",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "CODECOV_TOKEN", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "Codecov does not publish packages"},
			{Regex: `NPM_TOKEN`, Reason: "Codecov does not publish packages"},
			{Regex: `AWS_SECRET.*`, Reason: "Codecov does not need cloud credentials"},
			{Regex: `SSH_PRIVATE_KEY`, Reason: "Codecov does not need SSH access"},
			{Regex: `DOCKER_HUB.*`, Reason: "Codecov does not need Docker credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "sonarsource/sonarcloud-github-action",
		Owner:     "sonarsource",
		Name:      "sonarcloud-github-action",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "SONAR_TOKEN", Required: true},
			{Name: "GITHUB_TOKEN", Permissions: "pull-requests:write", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "SonarCloud does not publish packages"},
			{Regex: `NPM_TOKEN`, Reason: "SonarCloud does not publish packages"},
			{Regex: `AWS_SECRET.*`, Reason: "SonarCloud does not need cloud credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "hashicorp/setup-terraform",
		Owner:     "hashicorp",
		Name:      "setup-terraform",
		RiskTier:  TierLow,
	},
	{
		Ecosystem: "github_action",
		Reference: "helm/chart-releaser-action",
		Owner:     "helm",
		Name:      "chart-releaser-action",
		RiskTier:  TierCritical,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "contents:write", Required: true},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "softprops/action-gh-release",
		Owner:     "softprops",
		Name:      "action-gh-release",
		RiskTier:  TierHigh,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "contents:write", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "GitHub release does not need PyPI credentials"},
			{Regex: `NPM_TOKEN`, Reason: "GitHub release does not need npm credentials"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "slackapi/slack-github-action",
		Owner:     "slackapi",
		Name:      "slack-github-action",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "SLACK_WEBHOOK_URL", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "Slack notification does not need package credentials"},
			{Regex: `AWS_SECRET.*`, Reason: "Slack notification does not need cloud credentials"},
			{Regex: `SSH_PRIVATE_KEY`, Reason: "Slack notification does not need SSH access"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "goreleaser/goreleaser-action",
		Owner:     "goreleaser",
		Name:      "goreleaser-action",
		RiskTier:  TierCritical,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "contents:write", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "GoReleaser does not publish Python packages"},
			{Regex: `NPM_TOKEN`, Reason: "GoReleaser does not publish npm packages"},
		},
	},
	{
		Ecosystem: "github_action",
		Reference: "peter-evans/create-pull-request",
		Owner:     "peter-evans",
		Name:      "create-pull-request",
		RiskTier:  TierMedium,
		RequiredSecrets: []SecretRequirement{
			{Name: "GITHUB_TOKEN", Permissions: "pull-requests:write,contents:write", Required: true},
		},
		ForbiddenPatterns: []PatternDef{
			{Regex: `PYPI.*`, Reason: "PR creation does not need package credentials"},
			{Regex: `AWS_SECRET.*`, Reason: "PR creation does not need cloud credentials"},
		},
	},
}

// ValidateProfiles checks all embedded profiles for correctness.
// Called at init time to catch configuration bugs early.
func ValidateProfiles() error {
	for _, pd := range EmbeddedProfiles {
		if pd.Reference == "" {
			return fmt.Errorf("profile has empty reference")
		}
		if pd.Ecosystem == "" {
			return fmt.Errorf("profile %s has empty ecosystem", pd.Reference)
		}
		for _, pat := range pd.ForbiddenPatterns {
			if _, err := regexp.Compile(pat.Regex); err != nil {
				return fmt.Errorf("profile %s has invalid regex %q: %w", pd.Reference, pat.Regex, err)
			}
		}
	}
	return nil
}

// Bootstrap populates the graph with embedded security profiles.
// This creates Tool, Profile, Secret, and SecretPattern nodes along with
// their relationships. Uses a transaction for atomicity.
// Returns the count of profiles created for sanity checking.
func Bootstrap(ctx context.Context, g *tkgraph.Graph) (int, error) {
	if err := ValidateProfiles(); err != nil {
		return 0, fmt.Errorf("invalid embedded profiles: %w", err)
	}

	tx := g.BeginTx()
	defer tx.Rollback()

	count := 0
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
			return 0, fmt.Errorf("create tool %s: %w", pd.Reference, err)
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
			return 0, fmt.Errorf("create profile for %s: %w", pd.Reference, err)
		}

		// Link Tool → Profile.
		_, err = tx.AddRelationship(
			scggraph.RelHasProfile,
			toolNode, profileNode,
			nil,
		)
		count++
		if err != nil {
			return 0, fmt.Errorf("link tool→profile for %s: %w", pd.Reference, err)
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
				return 0, fmt.Errorf("create secret %s for %s: %w", req.Name, pd.Reference, err)
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
				return 0, fmt.Errorf("link profile→secret for %s: %w", pd.Reference, err)
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
				return 0, fmt.Errorf("create pattern %s for %s: %w", pat.Regex, pd.Reference, err)
			}

			_, err = tx.AddRelationship(
				scggraph.RelForbids,
				profileNode, patternNode,
				nil,
			)
			if err != nil {
				return 0, fmt.Errorf("link profile→pattern for %s: %w", pd.Reference, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// toolID extracts the Snowflake ID from a node for use in relationship creation.
func toolID(n *types.Node) int64 {
	return n.InternalID().SnowflakeID().Int64()
}
