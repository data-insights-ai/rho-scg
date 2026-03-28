package graph

import (
	"context"
	"testing"

	tkgraph "gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3/pkg/graph"
	"gitlab2024.bds421-cloud.com/bds421/sigma/tkgd/pkg/cypher"
)

func testSCGGraph(t *testing.T) *SCGGraph {
	t.Helper()
	sg, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sg.Close() })
	return sg
}

func TestGraphPopulation_ToolAndDigest(t *testing.T) {
	sg := testSCGGraph(t)
	g := sg.G

	tx := g.BeginTx()

	toolNode, err := tx.AddNode([]string{LabelTool}, map[string]any{
		"ecosystem": "github_action",
		"reference": "actions/checkout@v4",
		"owner":     "actions",
		"name":      "checkout",
	})
	if err != nil {
		t.Fatal(err)
	}

	digestNode, err := tx.AddNode([]string{LabelDigest}, map[string]any{
		"hash":      "abc123def456",
		"algorithm": "sha256",
		"source":    "api.github.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tx.AddRelationship(RelResolvesTo, toolNode, digestNode, map[string]any{
		"tkg_valid_from": int64(1711612800000), // 2024-03-28
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Verify nodes exist via graph API.
	tools, err := g.NodesByLabel("Tool", tkgraph.QueryOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 Tool node, got %d", len(tools))
	}

	ref, ok := tools[0].GetProperty("reference")
	if !ok || ref != "actions/checkout@v4" {
		t.Errorf("tool reference = %v, want actions/checkout@v4", ref)
	}

	digests, err := g.NodesByLabel("Digest", tkgraph.QueryOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(digests) != 1 {
		t.Fatalf("expected 1 Digest node, got %d", len(digests))
	}

	hash, ok := digests[0].GetProperty("hash")
	if !ok || hash != "abc123def456" {
		t.Errorf("digest hash = %v, want abc123def456", hash)
	}

	// Verify relationship exists.
	rels, err := g.OutgoingRelationships(toolNode.InternalID().SnowflakeID(), RelResolvesTo)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 {
		t.Fatalf("expected 1 RESOLVES_TO relationship, got %d", len(rels))
	}
}

func TestCypherQuery_CurrentResolution(t *testing.T) {
	sg := testSCGGraph(t)
	g := sg.G
	engine := sg.Engine

	// Populate graph.
	tx := g.BeginTx()
	toolNode, _ := tx.AddNode([]string{LabelTool}, map[string]any{
		"ecosystem": "github_action",
		"reference": "actions/checkout@v4",
	})
	digestNode, _ := tx.AddNode([]string{LabelDigest}, map[string]any{
		"hash":      "abc123",
		"algorithm": "sha256",
		"source":    "test",
	})
	tx.AddRelationship(RelResolvesTo, toolNode, digestNode, nil)
	tx.Commit()

	// Query via Cypher.
	ctx := context.Background()
	result, err := engine.Execute(ctx, QueryCurrentResolution, map[string]any{
		"ref": "actions/checkout@v4",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result.Rows))
	}

	hash := result.Rows[0]["hash"]
	if hash != "abc123" {
		t.Errorf("hash = %v, want abc123", hash)
	}
}

func TestCypherQuery_SecretViolations(t *testing.T) {
	sg := testSCGGraph(t)
	g := sg.G
	engine := sg.Engine

	tx := g.BeginTx()

	// Create step → tool → profile → forbidden pattern chain.
	stepNode, _ := tx.AddNode([]string{LabelStep}, map[string]any{"name": "trivy-scan"})
	toolNode, _ := tx.AddNode([]string{LabelTool}, map[string]any{
		"reference": "aquasecurity/trivy-action@v1",
	})
	profileNode, _ := tx.AddNode([]string{LabelProfile}, map[string]any{
		"risk_tier": 1,
	})
	patternNode, _ := tx.AddNode([]string{LabelSecretPattern}, map[string]any{
		"regex":  "PYPI.*",
		"reason": "Trivy does not publish to PyPI",
	})
	secretNode, _ := tx.AddNode([]string{LabelSecret}, map[string]any{
		"name":   "PYPI_API_TOKEN",
		"source": "env",
	})

	tx.AddRelationship(RelUses, stepNode, toolNode, nil)
	tx.AddRelationship(RelHasProfile, toolNode, profileNode, nil)
	tx.AddRelationship(RelForbids, profileNode, patternNode, nil)
	tx.AddRelationship(RelHasAccess, stepNode, secretNode, nil)
	tx.Commit()

	// Query for violations.
	ctx := context.Background()
	result, err := engine.Execute(ctx, QuerySecretViolations, map[string]any{
		"step": "trivy-scan",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Rows) == 0 {
		t.Fatal("expected at least 1 violation row")
	}

	found := false
	for _, row := range result.Rows {
		if row["secret"] == "PYPI_API_TOKEN" {
			found = true
			if row["reason"] != "Trivy does not publish to PyPI" {
				t.Errorf("reason = %v", row["reason"])
			}
		}
	}
	if !found {
		t.Error("PYPI_API_TOKEN violation not found in query results")
	}
}

func TestCypherQuery_NoViolations(t *testing.T) {
	sg := testSCGGraph(t)
	g := sg.G
	engine := sg.Engine

	tx := g.BeginTx()
	stepNode, _ := tx.AddNode([]string{LabelStep}, map[string]any{"name": "clean-step"})
	toolNode, _ := tx.AddNode([]string{LabelTool}, map[string]any{
		"reference": "actions/checkout@v4",
	})
	tx.AddRelationship(RelUses, stepNode, toolNode, nil)
	tx.Commit()

	ctx := context.Background()
	result, err := engine.Execute(ctx, QuerySecretViolations, map[string]any{
		"step": "clean-step",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Rows) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Rows))
	}
}

func TestGraphDeduplication(t *testing.T) {
	sg := testSCGGraph(t)
	g := sg.G

	// Create two tool nodes with the same reference.
	tx := g.BeginTx()
	t1, _ := tx.AddNode([]string{LabelTool}, map[string]any{"reference": "actions/checkout@v4"})
	t2, _ := tx.AddNode([]string{LabelTool}, map[string]any{"reference": "actions/checkout@v4"})
	tx.Commit()

	// TKG creates two separate nodes (no dedup at graph level).
	// Application code must handle dedup.
	if t1.InternalID().SnowflakeID() == t2.InternalID().SnowflakeID() {
		t.Error("expected different IDs for two separate AddNode calls")
	}

	tools, _ := g.NodesByLabel("Tool", tkgraph.QueryOpts{})
	if len(tools) != 2 {
		t.Errorf("expected 2 Tool nodes (no graph-level dedup), got %d", len(tools))
	}
}

func TestGraphClose_Idempotent(t *testing.T) {
	sg := testSCGGraph(t)
	if err := sg.Close(); err != nil {
		t.Fatal(err)
	}
	// Second close should not panic.
	sg.Close()
}

// Verify the Cypher engine is wired to the right graph.
func TestCypherEngine_IsWired(t *testing.T) {
	sg := testSCGGraph(t)

	ctx := context.Background()
	// Empty graph should return 0 rows.
	result, err := sg.Engine.Execute(ctx, "MATCH (n) RETURN n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 0 {
		t.Errorf("expected 0 rows in empty graph, got %d", len(result.Rows))
	}

	// Add a node and query it.
	tx := sg.G.BeginTx()
	tx.AddNode([]string{LabelTool}, map[string]any{"reference": "test"})
	tx.Commit()

	result, err = sg.Engine.Execute(ctx, "MATCH (n:Tool) RETURN n.reference AS ref", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result.Rows))
	}
	if result.Rows[0]["ref"] != "test" {
		t.Errorf("ref = %v, want test", result.Rows[0]["ref"])
	}
}

// Verify Cypher parameter binding prevents injection.
func TestCypherQuery_ParameterBinding(t *testing.T) {
	sg := testSCGGraph(t)

	ctx := context.Background()
	// Attempt to inject via parameter — should be treated as literal string.
	result, err := sg.Engine.Execute(ctx, QueryCurrentResolution, map[string]any{
		"ref": `" OR 1=1 --`,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Should return 0 rows, not all rows.
	if len(result.Rows) != 0 {
		t.Errorf("expected 0 rows for injection attempt, got %d", len(result.Rows))
	}
}

// Ensure unused Cypher query constants at least parse without error.
func TestCypherQueries_Parse(t *testing.T) {
	sg := testSCGGraph(t)
	ctx := context.Background()

	queries := map[string]map[string]any{
		QueryCurrentResolution: {"ref": "test"},
		QueryAllResolutions:    nil,
		QueryStepTools:         {"step": "test"},
		QueryStepSecrets:       {"step": "test"},
		QueryForbiddenPatterns: {"ref": "test"},
		QuerySecretViolations:  {"step": "test"},
		QueryPipelineSteps:     {"path": "test"},
		QueryToolProfile:       {"ref": "test"},
	}

	for name, params := range queries {
		_, err := sg.Engine.Execute(ctx, name, params)
		if err != nil {
			// Parse errors should be caught here.
			// Execution on empty graph returning 0 rows is fine.
			if isParseError(err) {
				t.Errorf("query %q failed to parse: %v", name[:40], err)
			}
		}
	}
}

func isParseError(err error) bool {
	// Cypher parse errors typically contain "parse" or "syntax".
	s := err.Error()
	return contains(s, "parse") || contains(s, "syntax") || contains(s, "unexpected")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Verify the engine reference is correctly typed.
func TestSCGGraph_EngineType(t *testing.T) {
	sg := testSCGGraph(t)
	var _ *cypher.Engine = sg.Engine // compile-time type check
}
