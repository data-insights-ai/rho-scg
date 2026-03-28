// Package testutil provides test helpers for SCG.
package testutil

import (
	"testing"

	scggraph "gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/graph"
)

// TestGraph creates an in-memory SCG graph for testing.
// The graph is automatically closed when the test finishes.
func TestGraph(t *testing.T) *scggraph.SCGGraph {
	t.Helper()

	sg, err := scggraph.New(scggraph.Config{})
	if err != nil {
		t.Fatalf("create test graph: %v", err)
	}

	t.Cleanup(func() {
		if err := sg.Close(); err != nil {
			t.Errorf("close test graph: %v", err)
		}
	})

	return sg
}
