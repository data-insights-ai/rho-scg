package graph

import (
	tkgraph "gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/graph"
)

// NewMemoryConfig returns a graph config using in-memory storage.
// Suitable for CLI mode where the graph is ephemeral per-run.
func NewMemoryConfig() tkgraph.Config {
	return tkgraph.Config{
		SnowflakeNodeID: 0,
	}
}

// NewBadgerConfig returns a graph config using persistent BadgerDB storage.
// Suitable for daemon mode where history is preserved across runs.
func NewBadgerConfig(dir string) tkgraph.Config {
	return tkgraph.Config{
		SnowflakeNodeID: 0,
		BadgerDir:       dir,
	}
}
