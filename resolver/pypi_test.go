package resolver

import "testing"

func TestParsePyPIRef(t *testing.T) {
	tests := []struct {
		input     string
		name      string
		version   string
		expectErr bool
	}{
		{"requests==2.31.0", "requests", "2.31.0", false},
		{"litellm==1.82.6", "litellm", "1.82.6", false},
		{"flask>=2.0.0", "flask", "2.0.0", false},
		{"numpy == 1.26.0", "numpy", "1.26.0", false},
		{"requests", "", "", true},
		{"", "", "", true},
	}

	for _, tt := range tests {
		name, version, err := parsePyPIRef(tt.input)
		if tt.expectErr {
			if err == nil {
				t.Errorf("parsePyPIRef(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePyPIRef(%q) error: %v", tt.input, err)
			continue
		}
		if name != tt.name {
			t.Errorf("parsePyPIRef(%q) name = %q, want %q", tt.input, name, tt.name)
		}
		if version != tt.version {
			t.Errorf("parsePyPIRef(%q) version = %q, want %q", tt.input, version, tt.version)
		}
	}
}

func TestNewPyPIResolver(t *testing.T) {
	r := NewPyPIResolver()
	if r.Ecosystem() != EcoPyPI {
		t.Errorf("ecosystem = %q, want %q", r.Ecosystem(), EcoPyPI)
	}
}
