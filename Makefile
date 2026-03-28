BINARY := scg
PKG := ./...
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test test-race check fmt fmt-check vet cover clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/scg/

test:
	go test -short -count=1 $(PKG)

test-race:
	go test -short -count=1 -race $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:"; gofmt -l .; exit 1)

cover:
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

check: fmt-check vet build test

ci: fmt-check vet build test-race

clean:
	rm -f $(BINARY) coverage.out coverage.html
