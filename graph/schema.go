// Package graph defines the SCG graph schema and provides a factory
// for creating TKG-backed graph instances with the Cypher query engine.
package graph

import (
	"fmt"

	tkgraph "gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/graph"
	"gitlab2024.bds421-cloud.com/bds421/sigma/tkgd/pkg/cypher"
)

// Node labels.
const (
	LabelTool          = "Tool"
	LabelDigest        = "Digest"
	LabelStep          = "Step"
	LabelSecret        = "Secret"
	LabelPipeline      = "Pipeline"
	LabelProfile       = "Profile"
	LabelSecretPattern = "SecretPattern"
)

// Relationship types.
const (
	RelResolvesTo   = "RESOLVES_TO"   // Tool → Digest (temporal)
	RelUses         = "USES"          // Step → Tool
	RelHasAccess    = "HAS_ACCESS"    // Step → Secret
	RelHasProfile   = "HAS_PROFILE"   // Tool → Profile
	RelRequires     = "REQUIRES"      // Profile → Secret
	RelForbids      = "FORBIDS"       // Profile → SecretPattern
	RelContainsStep = "CONTAINS_STEP" // Pipeline → Step
)

// AllLabels returns all node labels used in the SCG schema.
func AllLabels() []string {
	return []string{
		LabelTool, LabelDigest, LabelStep, LabelSecret,
		LabelPipeline, LabelProfile, LabelSecretPattern,
	}
}

// AllRelTypes returns all relationship types used in the SCG schema.
func AllRelTypes() []string {
	return []string{
		RelResolvesTo, RelUses, RelHasAccess, RelHasProfile,
		RelRequires, RelForbids, RelContainsStep,
	}
}

// SCGGraph wraps a TKG graph and a Cypher engine for SCG operations.
type SCGGraph struct {
	G      *tkgraph.Graph
	Engine *cypher.Engine
}

// Config controls how the SCG graph is created.
type Config struct {
	// BadgerDir sets the path for persistent storage.
	// Empty string uses in-memory storage (CLI default).
	BadgerDir string
}

// New creates a new SCG graph with the given configuration.
func New(cfg Config) (*SCGGraph, error) {
	var graphCfg tkgraph.Config
	if cfg.BadgerDir != "" {
		graphCfg = NewBadgerConfig(cfg.BadgerDir)
	} else {
		graphCfg = NewMemoryConfig()
	}

	g, err := tkgraph.New(graphCfg)
	if err != nil {
		return nil, fmt.Errorf("create graph: %w", err)
	}

	engine := cypher.NewEngine(g)

	return &SCGGraph{G: g, Engine: engine}, nil
}

// Close releases all resources held by the graph.
func (sg *SCGGraph) Close() error {
	return sg.G.Close()
}

// EnsureIndexes creates property indexes for frequently queried fields.
// Must be called AFTER nodes exist for each label (labels must be registered).
func (sg *SCGGraph) EnsureIndexes() {
	g := sg.G

	// Property indexes for fast lookups.
	g.CreatePropertyIndex(LabelTool, "reference")
	g.CreatePropertyIndex(LabelTool, "ecosystem")
	g.CreatePropertyIndex(LabelSecret, "name")
	g.CreatePropertyIndex(LabelDigest, "hash")
	g.CreatePropertyIndex(LabelProfile, "risk_tier")
}
