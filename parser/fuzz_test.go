package parser

import "testing"

// Fuzz tests for parsers. Run with:
//   go test -fuzz=FuzzWorkflowParse -fuzztime=30s ./parser/
//   go test -fuzz=FuzzDockerfileParse -fuzztime=30s ./parser/

func FuzzWorkflowParse(f *testing.F) {
	// Seed corpus with valid and interesting inputs.
	f.Add([]byte(`name: CI
on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@v4`))
	f.Add([]byte(`name: test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: test
        run: go test ./...
      - uses: docker/build-push-action@v5
        with:
          password: ${{ secrets.DOCKER_TOKEN }}
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`---`))

	p := NewWorkflowParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic for any input.
		p.Parse("fuzz.yml", data)
	})
}

func FuzzDockerfileParse(f *testing.F) {
	f.Add([]byte(`FROM alpine:3.19
RUN echo hi`))
	f.Add([]byte(`FROM golang:1.22-alpine AS builder
RUN go build
FROM scratch
COPY --from=builder /app /app`))
	f.Add([]byte(`# comment only`))
	f.Add([]byte(``))
	f.Add([]byte(`FROM ${BASE}:latest`))

	p := NewDockerfileParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic for any input.
		p.Parse("Dockerfile", data)
	})
}

func FuzzNPMParse(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/express":{"version":"4.21.0"}}}`))
	f.Add([]byte(`{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.21"}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"packages":{"node_modules/@scope/pkg":{"version":"1.0.0"}}}`))

	p := NewNPMPackageParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic for any input.
		p.Parse("package-lock.json", data)
	})
}

func FuzzPyPIParse(f *testing.F) {
	f.Add([]byte("requests==2.31.0\nflask>=2.0\n"))
	f.Add([]byte("# comment\nrequests[security]==2.28.0\n"))
	f.Add([]byte("-r other.txt\n-e git+https://example.com\n"))
	f.Add([]byte(""))
	f.Add([]byte("pkg==1.0 ; python_version >= \"3.8\"\n"))

	p := NewPyPIRequirementsParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic for any input.
		p.Parse("requirements.txt", data)
	})
}

// A lock file comes from the repository being checked, so it is input a
// stranger controls. Every other parser here is fuzzed; this one reads
// TOML and JSON through third-party decoders, which is more surface, not
// less.
func FuzzPythonLockParse(f *testing.F) {
	f.Add("poetry.lock", []byte("[[package]]\nname = \"certifi\"\nversion = \"2024.8.30\"\n"))
	f.Add("uv.lock", []byte("version = 1\n[[package]]\nname = \"httpx\"\nversion = \"0.27.2\"\nsource = { registry = \"https://pypi.org/simple\" }\n"))
	f.Add("uv.lock", []byte("[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n"))
	f.Add("Pipfile.lock", []byte(`{"default":{"requests":{"version":"==2.32.3"}},"develop":{}}`))
	f.Add("Pipfile.lock", []byte(`{"default":{"x":{"path":"./x"}}}`))
	f.Add("poetry.lock", []byte(""))
	f.Add("poetry.lock", []byte("[[package]]\nname = \"\"\nversion = \"\"\n"))
	f.Add("Pipfile.lock", []byte("{"))

	p := NewPythonLockParser()
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		// Only the three names this parser claims; anything else is not
		// its input and Parse is documented to reject it.
		switch name {
		case "poetry.lock", "uv.lock", "Pipfile.lock":
		default:
			return
		}
		// Must not panic for any input, and must not return a tool
		// without both a name and a version: an entry missing either is
		// not something that can be resolved, and letting one through
		// would put a meaningless reference in a baseline.
		wf, err := p.Parse(name, data)
		if err != nil || wf == nil {
			return
		}
		for _, tool := range wf.Tools {
			if tool.Name == "" || tool.Version == "" || tool.Reference != tool.Name+"@"+tool.Version {
				t.Fatalf("%s produced an unusable entry: %+v", name, tool)
			}
		}
	})
}
