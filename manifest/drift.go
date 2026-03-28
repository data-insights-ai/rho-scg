package manifest

import (
	"context"
	"fmt"

	"gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/resolver"
)

// Severity indicates the severity of a drift finding.
type Severity int

const (
	SevInfo     Severity = iota // digest unchanged, metadata updated
	SevWarning                  // new version available (expected)
	SevCritical                 // digest changed for same mutable ref (tag hijack!)
)

// String returns a human-readable severity label.
func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevWarning:
		return "WARNING"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// DriftResult represents a single drift finding.
type DriftResult struct {
	// Ecosystem is the dependency ecosystem.
	Ecosystem string

	// Reference is the mutable reference that drifted.
	Reference string

	// LockedHash is the hash recorded in the lockfile.
	LockedHash string

	// LiveHash is the hash from live resolution.
	LiveHash string

	// Severity indicates how critical this drift is.
	Severity Severity

	// Detail is a human-readable description of the drift.
	Detail string
}

// DetectDrift compares the lockfile against live resolution for each tool.
// Returns a list of drift results (empty if everything matches).
func DetectDrift(ctx context.Context, lf *Lockfile, resolvers map[resolver.Ecosystem]resolver.Resolver) ([]DriftResult, error) {
	var results []DriftResult

	for _, pipeline := range lf.Pipelines {
		for _, step := range pipeline.Steps {
			for _, tool := range step.Tools {
				eco := resolver.Ecosystem(tool.Ecosystem)
				res, ok := resolvers[eco]
				if !ok {
					continue
				}

				live, err := res.Resolve(ctx, tool.Reference)
				if err != nil {
					return nil, fmt.Errorf("resolve %s: %w", tool.Reference, err)
				}

				if live.Hash != tool.Hash {
					results = append(results, DriftResult{
						Ecosystem:  tool.Ecosystem,
						Reference:  tool.Reference,
						LockedHash: tool.Hash,
						LiveHash:   live.Hash,
						Severity:   SevCritical,
						Detail: fmt.Sprintf(
							"ALERT: %s resolved to different digest without version change. "+
								"Locked: %s, Live: %s. Possible tag hijack.",
							tool.Reference, tool.Hash[:minLen(len(tool.Hash), 16)],
							live.Hash[:minLen(len(live.Hash), 16)],
						),
					})
				}
			}
		}
	}

	return results, nil
}

func minLen(a, b int) int {
	if a < b {
		return a
	}
	return b
}
