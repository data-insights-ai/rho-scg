package resolver

import "testing"

// Fuzz tests for reference parsers. Run with:
//   go test -fuzz=FuzzParseActionRef -fuzztime=30s ./resolver/
//   go test -fuzz=FuzzParseDockerRef -fuzztime=30s ./resolver/
//   go test -fuzz=FuzzParsePyPIRef -fuzztime=30s ./resolver/
//   go test -fuzz=FuzzParseNPMRef -fuzztime=30s ./resolver/

func FuzzParseActionRef(f *testing.F) {
	f.Add("actions/checkout@v4")
	f.Add("owner/repo@sha256:abc123")
	f.Add("a/b@c")
	f.Add("")
	f.Add("@")
	f.Add("no-at-sign")

	f.Fuzz(func(t *testing.T, ref string) {
		parseActionRef(ref) // must not panic
	})
}

func FuzzParseDockerRef(f *testing.F) {
	f.Add("alpine:3.19")
	f.Add("ghcr.io/owner/image:tag")
	f.Add("registry:5000/app:v1")
	f.Add("alpine@sha256:abc123")
	f.Add("alpine")
	f.Add("")

	f.Fuzz(func(t *testing.T, ref string) {
		parseDockerRef(ref) // must not panic
	})
}

func FuzzParsePyPIRef(f *testing.F) {
	f.Add("requests==2.31.0")
	f.Add("flask>=2.0")
	f.Add("numpy")
	f.Add("")
	f.Add("==")

	f.Fuzz(func(t *testing.T, ref string) {
		parsePyPIRef(ref) // must not panic
	})
}

func FuzzParseNPMRef(f *testing.F) {
	f.Add("express@4.18.2")
	f.Add("@angular/core@17.0.0")
	f.Add("pkg")
	f.Add("")
	f.Add("@")

	f.Fuzz(func(t *testing.T, ref string) {
		parseNPMRef(ref) // must not panic
	})
}
