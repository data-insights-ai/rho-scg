package graph

import "testing"

func TestAllLabels(t *testing.T) {
	labels := AllLabels()
	if len(labels) != 7 {
		t.Errorf("expected 7 labels, got %d", len(labels))
	}

	want := map[string]bool{
		LabelTool: true, LabelDigest: true, LabelStep: true,
		LabelSecret: true, LabelPipeline: true, LabelProfile: true,
		LabelSecretPattern: true,
	}
	for _, l := range labels {
		if !want[l] {
			t.Errorf("unexpected label: %q", l)
		}
	}
}

func TestAllRelTypes(t *testing.T) {
	types := AllRelTypes()
	if len(types) != 7 {
		t.Errorf("expected 7 relationship types, got %d", len(types))
	}
}

func TestNewGraph_Memory(t *testing.T) {
	sg, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer sg.Close()

	if sg.G == nil {
		t.Error("graph is nil")
	}
	if sg.Engine == nil {
		t.Error("engine is nil")
	}
}

func TestNewGraph_EnsureIndexes(t *testing.T) {
	sg, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer sg.Close()

	// EnsureIndexes should not panic or error even with no nodes.
	sg.EnsureIndexes()
}
