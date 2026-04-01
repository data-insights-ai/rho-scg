package parser

import "testing"

func TestNPMPackageParser_Supports(t *testing.T) {
	p := NewNPMPackageParser()

	tests := []struct {
		path string
		want bool
	}{
		{"package-lock.json", true},
		{"/repo/package-lock.json", true},
		{"sub/dir/package-lock.json", true},
		{"package.json", false},
		{"package-lock.json.bak", false},
		{".github/workflows/ci.yml", false},
		{"requirements.txt", false},
		{"Dockerfile", false},
	}

	for _, tt := range tests {
		if got := p.Supports(tt.path); got != tt.want {
			t.Errorf("Supports(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestNPMPackageParser_Parse_V3(t *testing.T) {
	content := []byte(`{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.21.0"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/axios": {
      "version": "1.7.2"
    }
  }
}`)

	p := NewNPMPackageParser()
	wf, err := p.Parse("package-lock.json", content)
	if err != nil {
		t.Fatal(err)
	}

	if wf.Type != "npm" {
		t.Errorf("type = %q, want npm", wf.Type)
	}

	if len(wf.Tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(wf.Tools))
	}

	// Verify sorted order and reference format.
	expected := []struct {
		ref  string
		name string
		ver  string
	}{
		{"axios@1.7.2", "axios", "1.7.2"},
		{"express@4.21.0", "express", "4.21.0"},
		{"lodash@4.17.21", "lodash", "4.17.21"},
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
		if tool.Ecosystem != "npm" {
			t.Errorf("tool[%d].Ecosystem = %q, want npm", i, tool.Ecosystem)
		}
	}

	// Single step for all dependencies.
	if len(wf.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(wf.Steps))
	}
	if wf.Steps[0].Name != "dependencies" {
		t.Errorf("step name = %q, want dependencies", wf.Steps[0].Name)
	}
	if wf.Steps[0].Job != "npm-install" {
		t.Errorf("step job = %q, want npm-install", wf.Steps[0].Job)
	}
}

func TestNPMPackageParser_Parse_V1(t *testing.T) {
	content := []byte(`{
  "name": "legacy-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.0"
    },
    "body-parser": {
      "version": "1.20.0",
      "dependencies": {
        "debug": {
          "version": "2.6.9"
        }
      }
    }
  }
}`)

	p := NewNPMPackageParser()
	wf, err := p.Parse("package-lock.json", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 3 {
		t.Fatalf("tools = %d, want 3 (including nested debug)", len(wf.Tools))
		for _, tool := range wf.Tools {
			t.Logf("  %s", tool.Reference)
		}
	}

	refs := make(map[string]bool)
	for _, tool := range wf.Tools {
		refs[tool.Reference] = true
	}
	if !refs["express@4.18.0"] {
		t.Error("missing express@4.18.0")
	}
	if !refs["body-parser@1.20.0"] {
		t.Error("missing body-parser@1.20.0")
	}
	if !refs["debug@2.6.9"] {
		t.Error("missing debug@2.6.9")
	}
}

func TestNPMPackageParser_Parse_ScopedPackages(t *testing.T) {
	content := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
    "node_modules/@angular/core": {
      "version": "17.0.0"
    },
    "node_modules/@types/node": {
      "version": "20.10.0"
    }
  }
}`)

	p := NewNPMPackageParser()
	wf, err := p.Parse("package-lock.json", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(wf.Tools))
	}

	// Sorted: @angular/core before @types/node.
	if wf.Tools[0].Reference != "@angular/core@17.0.0" {
		t.Errorf("tool[0].Reference = %q, want @angular/core@17.0.0", wf.Tools[0].Reference)
	}
	if wf.Tools[0].Owner != "@angular" {
		t.Errorf("tool[0].Owner = %q, want @angular", wf.Tools[0].Owner)
	}
	if wf.Tools[0].Name != "@angular/core" {
		t.Errorf("tool[0].Name = %q, want @angular/core", wf.Tools[0].Name)
	}
	if wf.Tools[1].Reference != "@types/node@20.10.0" {
		t.Errorf("tool[1].Reference = %q, want @types/node@20.10.0", wf.Tools[1].Reference)
	}
}

func TestNPMPackageParser_Parse_Empty(t *testing.T) {
	content := []byte(`{}`)

	p := NewNPMPackageParser()
	wf, err := p.Parse("package-lock.json", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 0 {
		t.Errorf("tools = %d, want 0", len(wf.Tools))
	}
}

func TestNPMPackageParser_Parse_RootOnly(t *testing.T) {
	content := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "my-app", "version": "1.0.0" }
  }
}`)

	p := NewNPMPackageParser()
	wf, err := p.Parse("package-lock.json", content)
	if err != nil {
		t.Fatal(err)
	}

	if len(wf.Tools) != 0 {
		t.Errorf("tools = %d, want 0 (root-only lockfile)", len(wf.Tools))
	}
}

func TestNPMPackageParser_Parse_InvalidJSON(t *testing.T) {
	content := []byte(`not json at all`)

	p := NewNPMPackageParser()
	_, err := p.Parse("package-lock.json", content)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNPMPackageParser_Parse_DevDependencies(t *testing.T) {
	content := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
    "node_modules/express": {
      "version": "4.21.0"
    },
    "node_modules/eslint": {
      "version": "8.56.0",
      "dev": true
    }
  }
}`)

	p := NewNPMPackageParser()
	wf, err := p.Parse("package-lock.json", content)
	if err != nil {
		t.Fatal(err)
	}

	// Dev dependencies are included — SCG tracks all deps for integrity.
	if len(wf.Tools) != 2 {
		t.Fatalf("tools = %d, want 2 (including dev)", len(wf.Tools))
	}
}
