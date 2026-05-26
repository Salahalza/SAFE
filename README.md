# SAHM

**System for Artifact Harvesting and Management**

A standardized Windows field forensic acquisition platform for incident response.

## Status

Active development. v1.0 target: September 2026.

## Overview

SAHM (سهم) is a portable forensic acquisition system designed for IR field work.
Plug a prepared USB SSD into a target Windows machine, run the software, collect
verified evidence ready for lab analysis.

Core design principles:
- Non-destructive — never modifies the target system.
- Offline-first — no network dependency.
- Standardized — same workflow, every analyst, every case.
- Resilient — handles slow, hostile, or interrupted collection scenarios.

## Architecture

- Single static Go binary, no runtime dependencies.
- Modular: capability modules + tool adapters + profiles.
- Output: structured case folders with SHA-256 manifests.
- Compatible with Windows 10/11 and Server 2012 R2 through 2025.

## Documentation

- `MODULES_REFERENCE.md` — per-module command reference for the IR team.
- `DESIGN_QUESTIONS.md` — deferred design questions for post-v1 review.
- `CHANGELOG.md` — development log.

## Build

```bash
# Mac (for development)
go build -o sahm ./cmd/sahm

# Windows (cross-compiled)
GOOS=windows GOARCH=amd64 go build -o sahm.exe ./cmd/sahm
```

## Usage (current state)

```bash
./sahm.exe
```

Runs the `rapid_triage` profile against the local machine. Requires
administrator privileges for full collection. Output written to
`test-output/CASE-<timestamp>/`.