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
