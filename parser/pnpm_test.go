package parser

import "testing"

func TestPNPMLockParser_Supports(t *testing.T) {
	p := NewPNPMLockParser()
	if !p.Supports("pnpm-lock.yaml") || !p.Supports("sub/dir/pnpm-lock.yaml") {
		t.Error("should support pnpm-lock.yaml")
	}
	if p.Supports("package-lock.json") || p.Supports("yarn.lock") {
		t.Error("should not support non-pnpm lockfiles")
	}
}

// pnpm v9: keys are "name@version" (no leading slash), scoped packages quoted,
// peer variants carry a "(...)" suffix, non-registry deps lack integrity.
const pnpmV9 = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-AAAA==}

  '@babel/core@7.24.0':
    resolution: {integrity: sha512-BBBB==}

  react@18.3.1(typescript@5.4.0):
    resolution: {integrity: sha512-CCCC==}

  local-pkg@1.0.0:
    resolution: {directory: ../local, type: directory}
`

func TestPNPMLockParser_V9(t *testing.T) {
	wf, err := NewPNPMLockParser().Parse("pnpm-lock.yaml", []byte(pnpmV9))
	if err != nil {
		t.Fatal(err)
	}
	if wf.Type != "npm" {
		t.Errorf("type = %q, want npm", wf.Type)
	}

	// local-pkg has no integrity -> skipped. Three remain, sorted by reference.
	want := []struct{ ref, name, version, owner string }{
		{"@babel/core@7.24.0", "@babel/core", "7.24.0", "@babel"},
		{"lodash@4.17.21", "lodash", "4.17.21", ""},
		{"react@18.3.1", "react", "18.3.1", ""}, // peer suffix stripped
	}
	if len(wf.Tools) != len(want) {
		t.Fatalf("got %d tools, want %d: %+v", len(wf.Tools), len(want), wf.Tools)
	}
	for i, w := range want {
		got := wf.Tools[i]
		if got.Reference != w.ref || got.Name != w.name || got.Version != w.version || got.Owner != w.owner {
			t.Errorf("tool[%d] = %+v, want ref=%s name=%s ver=%s owner=%s", i, got, w.ref, w.name, w.version, w.owner)
		}
		if got.Ecosystem != "npm" || got.StepName != "dependencies" || got.JobName != "npm-install" {
			t.Errorf("tool[%d] metadata = eco:%s step:%s job:%s", i, got.Ecosystem, got.StepName, got.JobName)
		}
	}
}

// pnpm v6: keys carry a leading slash.
const pnpmV6 = `lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-AAAA==}
    dev: false

  /@babel/core@7.24.0:
    resolution: {integrity: sha512-BBBB==}
    dev: true
`

func TestPNPMLockParser_V6_StripsLeadingSlash(t *testing.T) {
	wf, err := NewPNPMLockParser().Parse("pnpm-lock.yaml", []byte(pnpmV6))
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Tools) != 2 {
		t.Fatalf("got %d tools, want 2: %+v", len(wf.Tools), wf.Tools)
	}
	if wf.Tools[0].Reference != "@babel/core@7.24.0" || wf.Tools[1].Reference != "lodash@4.17.21" {
		t.Errorf("refs = %q, %q; want @babel/core@7.24.0, lodash@4.17.21 (slash stripped)",
			wf.Tools[0].Reference, wf.Tools[1].Reference)
	}
}

func TestSplitPNPMKey(t *testing.T) {
	cases := []struct {
		in            string
		name, version string
		ok            bool
	}{
		{"lodash@4.17.21", "lodash", "4.17.21", true},
		{"/lodash@4.17.21", "lodash", "4.17.21", true},
		{"@babel/core@7.24.0", "@babel/core", "7.24.0", true},
		{"react@18.3.1(typescript@5.4.0)", "react", "18.3.1", true},
		{"/@scope/pkg@1.2.3-beta.4", "@scope/pkg", "1.2.3-beta.4", true},
		{"noversion", "", "", false},
	}
	for _, c := range cases {
		n, v, ok := splitPNPMKey(c.in)
		if n != c.name || v != c.version || ok != c.ok {
			t.Errorf("splitPNPMKey(%q) = %q,%q,%v; want %q,%q,%v", c.in, n, v, ok, c.name, c.version, c.ok)
		}
	}
}
