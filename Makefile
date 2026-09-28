# SAFE build targets.
#
# IMPORTANT: the Windows binary for VM testing MUST land in test-output/vm/ —
# the only folder the test VM has access to. NEVER build it to the repo root.
# Use `make vm`; the output path is baked in here so no session has to remember
# it. test-output/ is gitignored, so the binary is never committed.

VM_DIR := test-output/vm/bin
VM_EXE := $(VM_DIR)/safe-collect.exe
ANALYZE_DIR := test-output/host
ANALYZE_EXE := $(ANALYZE_DIR)/safe-analyze

.PHONY: vm analyze build vet lint check debug

# Detect OS and Shell
ifeq ($(OS),Windows_NT)
    # Check if 'sh' is available by running a test command
    HAS_SH := $(shell sh -c "echo 1" 2> nul)
    ifeq ($(HAS_SH),1)
        DETECTED_OS := Windows_sh
    else
        DETECTED_OS := Windows_cmd
    endif
    ANALYZE_EXE := $(ANALYZE_DIR)/safe-analyze.exe
else
    DETECTED_OS := Unix
endif

ifeq ($(DETECTED_OS),Windows_cmd)
    MKDIR_CMD = if not exist "test-output\vm\bin" mkdir "test-output\vm\bin"
    MKDIR_ANALYZE_CMD = if not exist "test-output\host" mkdir "test-output\host"
    BUILD_CMD = set GOOS=windows&& set GOARCH=amd64&& go build -o $(VM_EXE) ./cmd/safe-collect
    BUILD_ANALYZE_CMD = go build -o $(ANALYZE_EXE) ./cmd/safe-analyze
else
    MKDIR_CMD = mkdir -p $(VM_DIR)
    MKDIR_ANALYZE_CMD = mkdir -p $(ANALYZE_DIR)
    BUILD_CMD = GOOS=windows GOARCH=amd64 go build -o $(VM_EXE) ./cmd/safe-collect
    BUILD_ANALYZE_CMD = go build -o $(ANALYZE_EXE) ./cmd/safe-analyze
endif

# Cross-compile the Windows binary into the VM-accessible folder.
# This is THE command to produce a build for VM testing.
vm:
	@$(MKDIR_CMD)
	$(BUILD_CMD)
	@echo "built $(VM_EXE)"
	@powershell -ExecutionPolicy Bypass -File scripts\sync_to_vm.ps1

analyze:
	@$(MKDIR_ANALYZE_CMD)
	$(BUILD_ANALYZE_CMD)
	@echo "built $(ANALYZE_EXE)"

# Local compile check (no binary emitted). Must pass before any commit.
build:
	go build ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# Standard pre-handoff check: compile, lint, vet, and produce the VM binary.
check: build lint vet vm analyze

debug:
	@echo OS is $(OS)
	@echo SHELL is $(SHELL)
	@echo DETECTED_OS is $(DETECTED_OS)
	@echo HAS_SH is $(HAS_SH)

