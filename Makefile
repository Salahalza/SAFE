# SAFE Build Targets
#
# This Makefile provides standard commands for building and testing SAFE.

COLLECT_EXE := safe-collect.exe
ANALYZE_EXE := safe-analyze.exe

.PHONY: all build collect analyze clean test vet lint

all: build

build: collect analyze

collect:
	@echo "Building safe-collect for Windows..."
	@set GOOS=windows&& set GOARCH=amd64&& go build -o $(COLLECT_EXE) ./cmd/safe-collect

analyze:
	@echo "Building safe-analyze for current OS..."
	@go build -o $(ANALYZE_EXE) ./cmd/safe-analyze

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	@echo "Cleaning up build artifacts..."
	@if exist $(COLLECT_EXE) del $(COLLECT_EXE)
	@if exist $(ANALYZE_EXE) del $(ANALYZE_EXE)
