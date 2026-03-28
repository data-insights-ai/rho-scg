package resolver

import "testing"

func TestParseNPMRef(t *testing.T) {
	tests := []struct {
		input     string
		name      string
		version   string
		expectErr bool
	}{
		{"express@4.18.2", "express", "4.18.2", false},
		{"eslint@9.0.0", "eslint", "9.0.0", false},
		{"@angular/core@17.0.0", "@angular/core", "17.0.0", false},
		{"@types/node@20.0.0", "@types/node", "20.0.0", false},
		{"express", "", "", true},
		{"@scope/pkg", "", "", true},
		{"", "", "", true},
	}

	for _, tt := range tests {
		name, version, err := parseNPMRef(tt.input)
		if tt.expectErr {
			if err == nil {
				t.Errorf("parseNPMRef(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseNPMRef(%q) error: %v", tt.input, err)
			continue
		}
		if name != tt.name {
			t.Errorf("parseNPMRef(%q) name = %q, want %q", tt.input, name, tt.name)
		}
		if version != tt.version {
			t.Errorf("parseNPMRef(%q) version = %q, want %q", tt.input, version, tt.version)
		}
	}
}

func TestNewNPMResolver(t *testing.T) {
	r := NewNPMResolver()
	if r.Ecosystem() != EcoNPM {
		t.Errorf("ecosystem = %q, want %q", r.Ecosystem(), EcoNPM)
	}
}
