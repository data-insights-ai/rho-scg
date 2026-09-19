BINARY := scg
PKG := ./...
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test test-race check fmt fmt-check vet cover cover-gate lint clean

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

ci: fmt-check vet lint build test-race

clean:
	rm -f $(BINARY) coverage.out coverage.html

# cover-gate enforces the coverage floor declared in CLAUDE.md. Coverage that
# is only measured is coverage that drifts down.
COVER_MIN ?= 75
cover-gate:
	@go test -short -count=1 -coverprofile=coverage.out $(PKG) >/dev/null
	@go tool cover -func=coverage.out | awk -v min=$(COVER_MIN) ' \
		/^total:/ { total=$$3+0 } \
		END { \
			gsub("%","",total); \
			if (total < min) { \
				printf("coverage %.1f%% is below the %d%% gate\n", total, min); \
				exit 1 \
			} \
			printf("coverage %.1f%% meets the %d%% gate\n", total, min) \
		}'

lint:
	golangci-lint run --timeout 5m
