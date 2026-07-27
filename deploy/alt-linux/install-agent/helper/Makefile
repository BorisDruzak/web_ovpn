GO ?= go
OUTPUT ?= bin/alt-install-helper

.PHONY: build test

build:
	mkdir -p "$(dir $(OUTPUT))"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$(GO)" build -trimpath -buildvcs=false -ldflags="-buildid=" -o "$(OUTPUT)" ./cmd/alt-install-helper

test:
	"$(GO)" test ./...
