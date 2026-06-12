# SAFE build targets.
#
# IMPORTANT: the Windows binary for VM testing MUST land in test-output/vm/ —
# the only folder the test VM has access to. NEVER build it to the repo root.
# Use `make vm`; the output path is baked in here so no session has to remember
# it. test-output/ is gitignored, so the binary is never committed.

VM_DIR := test-output/vm
VM_EXE := $(VM_DIR)/safe.exe

.PHONY: vm build vet check

# Cross-compile the Windows binary into the VM-accessible folder.
# This is THE command to produce a build for VM testing.
vm:
	@mkdir -p $(VM_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(VM_EXE) ./cmd/safe
	@echo "built $(VM_EXE)"

# Local compile check (no binary emitted). Must pass before any commit.
build:
	go build ./...

vet:
	go vet ./...

# Standard pre-handoff check: compile, vet, and produce the VM binary.
check: build vet vm
