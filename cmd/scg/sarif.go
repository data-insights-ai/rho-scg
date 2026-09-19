package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/data-insights-ai/rho-scg/manifest"
)

// SARIF 2.1.0, the format GitHub code scanning ingests.
//
// Without it, findings live only in the job log: a red build with a wall of
// text somebody has to read. With it, drift appears in the repository's
// Security tab, annotated on the workflow file that pins the reference, and
// stays visible after the log has rotated away.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spectification/master/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name"`
	ShortDescription     sarifText        `json:"shortDescription"`
	FullDescription      sarifText        `json:"fullDescription"`
	DefaultConfiguration sarifRuleDefault `json:"defaultConfiguration"`
}

type sarifRuleDefault struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// SARIF rule identifiers. They are stable strings because GitHub keys alert
// dedup and "dismissed" state off them: renaming one resurfaces every alert a
// team has already triaged.
const (
	ruleDrift = "SCG001"
	ruleStale = "SCG002"
)

// writeSARIF renders drift findings and unverifiable entries as a SARIF report.
//
// lockfilePath locates the findings. A digest is not a source location, so
// every result is attributed to the lockfile that pins it — which is the file
// a reviewer has to change anyway.
func writeSARIF(w io.Writer, lockfilePath string, drift []manifest.DriftResult, warnings []string) error {
	report := sarifReport{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Supply Chain Guardian",
				Version:        version,
				InformationURI: "https://scg.data-insights.ai",
				Rules: []sarifRule{
					{
						ID:               ruleDrift,
						Name:             "DependencyDigestDrift",
						ShortDescription: sarifText{Text: "A pinned dependency now resolves to a different digest"},
						FullDescription: sarifText{Text: "The reference recorded in scg.lock resolves to a " +
							"different content digest than the one that was locked. For a floating tag this " +
							"means the tag was repointed, which is how a supply chain attack reaches a pipeline " +
							"that pinned a version but not a digest."},
						DefaultConfiguration: sarifRuleDefault{Level: "error"},
					},
					{
						ID:               ruleStale,
						Name:             "DependencyNotVerified",
						ShortDescription: sarifText{Text: "A pinned dependency could not be verified"},
						FullDescription: sarifText{Text: "SCG could not confirm this reference against its " +
							"registry: the platform was unreachable, the request budget was spent, or its " +
							"record was too old to trust. This is not a detection — nothing is known about " +
							"the dependency either way."},
						DefaultConfiguration: sarifRuleDefault{Level: "warning"},
					},
				},
			}},
			Results: sarifResults(lockfilePath, drift, warnings),
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func sarifResults(lockfilePath string, drift []manifest.DriftResult, warnings []string) []sarifResult {
	// Never nil: SARIF consumers treat a missing results array as a malformed
	// run, whereas an empty one correctly means "clean".
	results := make([]sarifResult, 0, len(drift)+len(warnings))

	loc := []sarifLocation{{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifact{URI: lockfilePath},
		},
	}}

	for _, d := range drift {
		results = append(results, sarifResult{
			RuleID: ruleDrift,
			Level:  "error",
			Message: sarifText{Text: fmt.Sprintf(
				"%s (%s) resolves to %s but scg.lock pins %s. The tag has moved since it was locked.",
				d.Reference, d.Ecosystem, d.LiveHash, d.LockedHash)},
			Locations: loc,
		})
	}

	for _, warning := range warnings {
		results = append(results, sarifResult{
			RuleID:    ruleStale,
			Level:     "warning",
			Message:   sarifText{Text: warning},
			Locations: loc,
		})
	}

	return results
}
