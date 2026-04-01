package parser

import "testing"

func TestPyPIRequirementsParser_Supports(t *testing.T) {
	p := NewPyPIRequirementsParser()

	tests := []struct {
		path string
		want bool
	}{
		{"requirements.txt", true},
		{"/repo/requirements.txt", true},
		{"requirements-dev.txt", true},
		{"requirements-test.txt", true},
		{"sub/dir/requirements.txt", true},
		{"package-lock.json", false},
		{"Dockerfile", false},
		{".github/workflows/ci.yml", false},
		{"my-requirements.txt", false},
		{"requirements.in", false},
	}

	for _, tt := range tests {
		if got := p.Supports(tt.path); got != tt.want {
			t.Errorf("Supports(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPyPIRequirementsParser_Parse_Basic(t *testing.T) {
	content := []byte(`requests==2.31.0
flask==3.0.0
boto3==1.34.0
`)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	if wf.Type != "pypi" {
		t.Errorf("type = %q, want pypi", wf.Type)
	}

	if len(wf.Tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(wf.Tools))
	}

	// Sorted order.
	expected := []struct {
		ref  string
		name string
		ver  string
	}{
		{"boto3@1.34.0", "boto3", "1.34.0"},
		{"flask@3.0.0", "flask", "3.0.0"},
		{"requests@2.31.0", "requests", "2.31.0"},
	}

	for i, exp := range expected {
		tool := wf.Tools[i]
		if tool.Reference != exp.ref {
			t.Errorf("tool[%d].Reference = %q, want %q", i, tool.Reference, exp.ref)
		}
		if tool.Name != exp.name {
			t.Errorf("tool[%d].Name = %q, want %q", i, tool.Name, exp.name)
		}
		if tool.Version != exp.ver {
			t.Errorf("tool[%d].Version = %q, want %q", i, tool.Version, exp.ver)
		}
		if tool.Ecosystem != "pypi" {
			t.Errorf("tool[%d].Ecosystem = %q, want pypi", i, tool.Ecosystem)
		}
	}

	// Single step for all dependencies.
	if len(wf.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(wf.Steps))
	}
	if wf.Steps[0].Name != "dependencies" {
		t.Errorf("step name = %q, want dependencies", wf.Steps[0].Name)
	}
	if wf.Steps[0].Job != "pip-install" {
		t.Errorf("step job = %q, want pip-install", wf.Steps[0].Job)
	}
}

func TestPyPIRequirementsParser_Parse_Empty(t *testing.T) {
	content := []byte(``)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 0 {
		t.Errorf("tools = %d, want 0", len(wf.Tools))
	}
}

func TestPyPIRequirementsParser_Parse_CommentsOnly(t *testing.T) {
	content := []byte(`# This is a comment
# Another comment

# Blank lines too
`)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 0 {
		t.Errorf("tools = %d, want 0", len(wf.Tools))
	}
}

func TestPyPIRequirementsParser_Parse_VersionOperators(t *testing.T) {
	content := []byte(`requests==2.31.0
boto3>=1.34.0
numpy~=1.26.0
pandas
scipy>1.11
`)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	// requests (==), boto3 (>=), numpy (~=) are included.
	// pandas (no version) and scipy (> only) are skipped.
	if len(wf.Tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(wf.Tools))
	}

	refs := make(map[string]bool)
	for _, tool := range wf.Tools {
		refs[tool.Reference] = true
	}
	if !refs["requests@2.31.0"] {
		t.Error("missing requests@2.31.0")
	}
	if !refs["boto3@1.34.0"] {
		t.Error("missing boto3@1.34.0")
	}
	if !refs["numpy@1.26.0"] {
		t.Error("missing numpy@1.26.0")
	}
}

func TestPyPIRequirementsParser_Parse_Extras(t *testing.T) {
	content := []byte(`requests[security]==2.28.0
celery[redis,auth]==5.3.0
`)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(wf.Tools))
	}

	// Extras stripped from name.
	refs := make(map[string]bool)
	for _, tool := range wf.Tools {
		refs[tool.Reference] = true
	}
	if !refs["requests@2.28.0"] {
		t.Error("missing requests@2.28.0 (extras should be stripped)")
	}
	if !refs["celery@5.3.0"] {
		t.Error("missing celery@5.3.0 (extras should be stripped)")
	}
}

func TestPyPIRequirementsParser_Parse_InlineComments(t *testing.T) {
	content := []byte(`flask==2.0.0  # web framework
requests==2.31.0 # HTTP client
`)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(wf.Tools))
	}
}

func TestPyPIRequirementsParser_Parse_Options(t *testing.T) {
	content := []byte(`--index-url https://pypi.org/simple/
-r other-requirements.txt
-e git+https://github.com/org/repo.git
-c constraints.txt
-f https://download.pytorch.org/whl/
requests==2.31.0
`)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	// Only requests should be parsed; all option lines skipped.
	if len(wf.Tools) != 1 {
		t.Fatalf("tools = %d, want 1", len(wf.Tools))
	}
	if wf.Tools[0].Reference != "requests@2.31.0" {
		t.Errorf("tool[0].Reference = %q, want requests@2.31.0", wf.Tools[0].Reference)
	}
}

func TestPyPIRequirementsParser_Parse_EnvironmentMarkers(t *testing.T) {
	content := []byte(`pywin32==306 ; sys_platform == "win32"
requests==2.31.0 ; python_version >= "3.8"
`)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	// Both should be parsed; markers stripped.
	if len(wf.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(wf.Tools))
	}
}

func TestPyPIRequirementsParser_Parse_NoVersion(t *testing.T) {
	content := []byte(`requests
flask
`)

	p := NewPyPIRequirementsParser()
	wf, err := p.Parse("requirements.txt", content)
	if err != nil {
		t.Fatal(err)
	}

	// Bare package names without versions are skipped.
	if len(wf.Tools) != 0 {
		t.Errorf("tools = %d, want 0 (bare names skipped)", len(wf.Tools))
	}
}
