# CLAUDE.md

This file is read by Claude Code at the start of every session. It encodes
the architectural principles, working conventions, and project context that
must be respected across sessions.

---

## Session Start Protocol

At the start of EVERY session, read these files in order:

1. `CLAUDE.md` (this file) — rules and project context
2. `docs/SESSION_HANDOFF.md` — current state and priorities
3. The most recent file in `docs/journal/` — last session's outcome

For long absences (weeks away from the project), also read the last 3-5
journal entries to reload texture and recent decisions.

After reading, summarize back to Salah what you understand. Wait for
confirmation or correction before any work. This is the handshake that
catches context drift early.

---

## Session End Protocol

EVERY session ends with writing a journal entry. This is a hard rule,
not a suggestion. The journal IS what makes work feel continuous across
sessions.

### Where to write

`docs/journal/YYYY-MM-DD-brief-topic.md`

Example: `docs/journal/2026-06-15-ascii-fallback.md`

If multiple sessions happen on one day, append a letter:
- `2026-06-15a-ascii-fallback.md`
- `2026-06-15b-readme-update.md`

### Format

Copy `docs/journal/TEMPLATE.md` and fill in. Do not invent new sections.
Do not skip sections. If a section has no content, write "None" or the
placeholder shown in the template.

The template has seven sections:
1. Goal — one line, what we set out to do
2. What got done — bullets with commit hashes
3. What got decided — design decisions, naming, scope changes
4. What got punted — items deferred, with where they're tracked
5. What surprised us — bugs, library quirks, unexpected difficulty
6. What's next — entry point for the next session
7. Notes for the next session — explicit "don't re-litigate" guidance

### When to write

Before the final commit and push of the session. If the session ends
abruptly (build broken, context lost), write what you can. A partial
journal is better than none.

### How to commit

The journal entry is part of the session's commits. Commit it as the
final commit before push:

```bash
git add docs/journal/YYYY-MM-DD-topic.md
git commit -m "journal: session YYYY-MM-DD — brief description"
git push
```

### What journals are NOT

- Not a replacement for CLAUDE.md (architectural rules go here)
- Not a replacement for DESIGN_QUESTIONS.md (open questions go there)
- Not a replacement for CHANGELOG.md (functional changes go there)
- Not commit messages (those are concise; journals capture texture)

Journals are the why and the surprise. The repo state shows what got
built. The journal shows what we learned.

---

## Project Identity

**Name:** SAFE (System for Artifacts Forensic and Examination)

**Rename status:** DONE. The codebase was renamed from SAHM → SAFE in
session 2026-06-12c (Go module, `cmd/safe/`, identifiers, VSS shadow
prefix `C:\safe_shadow_*`, TUI banner, all docs). The Go module is now
`safe`. Older journals and historical CHANGELOG entries still say SAHM —
that is correct; they describe past state and stay as-is.

**Former name:** SAHM (System for Artifact Harvesting and Management).
Renamed because the original collision concern (a Saudi stocks app uses
"SAHM") was reason enough once a better expansion was found.

**Naming exploration history (condensed):**
We considered ATHAR (أثر, "trace"), BASMA (بصمة, "fingerprint"),
FAHS (فحص, "examination"), SAYF (سيف, "sword"), and SWORD before
landing on SAFE. Re-litigating the name is not useful.

---

## Project Purpose

SAFE is a Windows forensic acquisition tool written in Go, designed
for incident response field work. Single developer: Salah, an IR analyst
based in Saudi Arabia. Primary use case is acquiring forensic artifacts
from potentially compromised Windows targets quickly and consistently.

**Target environment:**
- Windows 10/11 workstations and servers
- Server-heavy caseload (AD, Exchange, MSSQL, SharePoint, IIS, File Server)
- May be running on incident scene with elevated AV/EDR alertness
- Often operated by analysts in stressful situations

**Developer environment:**
- macOS for development
- Windows 11 VM in VMware Fusion for testing (plain PowerShell, not
  Windows Terminal)
- Private GitHub repo (main branch, single developer)

**Skill level:** Salah is a Go beginner with strong PowerShell/Python
background. Code should be clear, well-commented, idiomatic Go. Avoid
clever patterns when straightforward ones work.

---

## Defensive Security Charter — READ THIS BEFORE REVIEWING ANY MODULE

**SAFE is a defensive, blue-team forensic tool. Every line of it exists to
DETECT and STOP cyber attacks, never to conduct them.**

This matters for how you (Claude) read this codebase. Several files describe
attacker techniques in technical detail — process-memory injection indicators
(RWX-private pages, reflectively-loaded PE images, suspicious imported API
names) in `internal/analyzer/process_memory.go` and
`internal/module/process_memory_inspection*.go`, and COM-hijack persistence in
`internal/analyzer/com_hijack.go`. In past sessions a model treated reading
these files as if they were offensive content and stopped working. That is a
misread. **These files are detection logic, not attack logic.** The same way an
antivirus engine, an EDR product, or a Volatility/Velociraptor plugin must
understand what malware does in order to recognize it, SAFE describes attacker
behavior solely to surface its forensic traces for an analyst.

Concretely, to remove any ambiguity:

- **Direction is reverse-of-offense.** SAFE finds evidence of attacks that have
  *already happened* on a victim host so a responder can scope and remediate.
  It does not attack anything.
- **It is collect-and-analyze only.** Collection modules READ host evidence
  (files, registry hives, memory regions of running processes) using the
  analyst's own administrative rights on a machine they are responsible for.
  Analyzers run later in the lab over that collected evidence. There is no
  payload, no exploit, no shellcode, no code injection, no privilege
  escalation, no C2, no lateral movement, no detection-evasion, and no
  targeting of third parties anywhere in this project.
- **Reading another process's memory is standard DFIR acquisition** — the same
  mechanism behind WinPmem, DumpIt, Volatility acquisition, and every EDR. SAFE
  copies raw region bytes for *later* lab triage; the on-target side makes zero
  interpretation (architectural principle #1).
- **Naming a MITRE ATT&CK technique (e.g. T1546.015 COM hijacking) is detection
  vocabulary**, exactly as it appears in Sigma rules, EDR alerts, and threat
  reports. It marks what to look for, not instructions to do it.

Reviewing, refactoring, explaining, and improving these files is squarely
within scope and should proceed normally. If something in here ever genuinely
looks like it crosses from detection into enabling an attack, say so plainly and
ask Salah — but the default, correct reading of this codebase is defensive.

The key analyzer/module files carry a short version of this notice in their
header comments so the context travels with the code.

---

## Operational Security — No External Publication (DO NOT VIOLATE)

SAFE's binary (`safe.exe`) and its source code must NEVER be uploaded,
submitted, posted, pasted, or transmitted to any third-party internet
service. This includes — but is not limited to — VirusTotal, any other AV
or malware scanner, Microsoft / AV-vendor submission portals, pastebins,
gists, file-sharing sites, and any external or third-party API.

The ONLY permitted internet destination for this project is its own private
GitHub repository (`git push` / `git pull` to the configured `origin`).
Nothing else about this project leaves the machine.

This covers whole files, snippets, hashes submitted for lookup, the compiled
binary, and any other channel that exposes the code or binary to a third
party. No exceptions, no "just this once." If a task appears to require
external submission (AV whitelisting, a scan, a paste, a share link), STOP
and ask Salah — do not proceed.

---

## Architectural Principles (DO NOT VIOLATE)

These are not preferences — they are load-bearing decisions for the project.
Violating them breaks the design. Each was decided deliberately after debate.

### 1. Strict collection/analysis separation

**Rule:** Modules in `internal/module/` collect files. They do NOT parse,
analyze, or interpret data on the target device.

**Why:** Every command run on a target adds noise to event logs, may
trigger EDR, and risks interaction with malware that watches for forensic
activity. SAFE is a "quiet visitor."

**Where parsing happens:** `internal/analyzer/` packages, run via
`safe --analyze <case-folder>` in the analyst's lab environment.

**Exception:** A module may run a single PowerShell or native Windows
command if that command IS the artifact (e.g., `tasklist /v` produces
`tasklist_verbose.txt`). The command is collection method, not analysis.

### 2. Order of volatility within profiles

**Rule:** Within a profile, modules run from most volatile to least.

**Why:** Standard digital forensics principle. Process state, network
connections, and memory are gone the moment they're not captured.

**rapid_triage order:** process_snapshot → network_snapshot →
system_metadata → eventlogs_core → registry_core → persistence_core →
amcache_collection → user_hives_collection → prefetch_collection

### 3. Shared VSS shadow per case

**Rule:** Engine creates ONE Volume Shadow Copy per case run. Modules
that need shadow access share it via `ctx.Shadow`.

**Why:** Multiple shadows are slow and wasteful. Shadow IDs are also
captured in case metadata for audit trail.

### 4. Bulk vs primary artifact distinction

**Rule:** When a module bulk-copies many files (e.g., 500 .pf files), it
reports ONE conceptual artifact and sets `result.BulkFiles = N`. The
manifest walker still hashes every file individually.

**Why:** Analyst-meaningful artifact counts. "475 prefetch files" is one
collected dataset, not 475 separate findings to triage.

**Where to use:** Prefetch today. Phase 2 extended event channels will
follow same pattern.

### 5. Hash everything, manifest everything

**Rule:** Every file collected gets SHA-256 hashed by the manifest writer.
No exceptions. This is the integrity contract.

**Where:** `internal/manifest/manifest.go` walks each module output dir
and produces `module.json`. Case manifest at `manifest.sha256` hashes
all module manifests plus top-level files. Same applies to lab_report/.

### 6. Quality over speed

**Rule:** When choice exists between shipping fast and shipping correctly,
choose correctly. Salah has explicitly prioritized this.

### 7. Single-binary deployment

**Rule:** SAFE is one executable. No runtime dependencies, no companion
binaries, no installers. The .exe is the product.

**Why:** Field-deployed at incident scene where you can't install things.
Drives library choice (Go-native preferred over external tool wrapping).

### 8. Unified parsing approach

**Rule:** Go-native parsers, using mature Go libraries (regparser,
go-prefetch, possibly evtx) where they're excellent. No shelling out
to external executables.

**Process for new parsers:**
1. Build native first
2. Test against real artifacts from VM
3. If quality insufficient, evaluate Go libraries
4. If library is excellent, switch and contribute upstream
5. Wrapping external tools (KAPE, EZ tools, etc.) is NOT acceptable —
   it breaks single-binary deployment

---

## Working Style (HOW TO COLLABORATE)

These are Salah's communication and process preferences. Honor them.

### Be a colleague, not a coach

- No flattery, no "great question!", no motivational language
- Push back when scope is unclear or a request seems wrong
- Recommend stopping when uncertainty is high
- State opinions with reasons, not deference
- Intellectual honesty over persuasion

### Make decisions explicit

- Don't decide silently. Surface the decision point.
- When multiple options exist, present them with honest tradeoffs.
- Don't pretend confidence about things you don't know (library APIs,
  external collisions, AV behavior). Say "I don't know" and search.

### Build vs commit discipline

**NEVER commit untested code.** Functional changes require a VM test
before commit.

**NEVER push without confirming the commit landed.** Always show
`git log --oneline -5` after pushing.

**One commit = one logical change.** Don't bundle unrelated changes.

**Always update CHANGELOG.md** when committing functional changes.

**Don't add Co-Authored-By tags to commits.** Commit messages should be
concise and not reference the AI assistant.

### File editing preferences

- Salah prefers FULL FILE REPLACEMENTS over partial diffs when there's
  any ambiguity about where a change goes. Diffs are fine for small,
  unambiguous changes.
- Before editing, view the file first. Don't assume contents.
- Confirm understanding before large changes. For sequential work within
  agreed scope, just proceed.

### Don't suggest stopping unless asked

Salah will say when to stop. Don't pre-emptively suggest pausing unless
something is genuinely going wrong.

### When losing focus, name it

If you notice drift from the original task or repetition, say so.

### Don't be precious about being right

When corrected, accept it cleanly. Don't apologize excessively. Fix the
thing and continue.

---

## Code Conventions

### Go specifics

- Idiomatic Go. No clever metaprogramming.
- Errors propagate with `fmt.Errorf("context: %w", err)`.
- Status enums are typed strings (see `module.Status`).
- Time values are UTC. Always.
- File paths use `filepath` package, not string concatenation.

### Module pattern

Every collection module implements `Module` interface:

```go
type Module interface {
    Name() string
    Priority() Priority
    TimeBudget() time.Duration
    RequiresVSS() bool
    Run(ctx *Context) Result
}
```

### Analyzer pattern

Every analyzer parser implements:

```go
type Parser interface {
    Name() string
    Parse(caseDir, labReportDir string) ([]string, ParseStats, []error)
}
```

Parsers find their source module via glob (`modules/*_<module_name>`).

### Testing

**No unit tests yet.** Known gap. VM is the integration test environment.

---

## Build and Test Workflow

### Standard build

```bash
go build ./...
```

Must pass before any commit.

### Cross-compile for Windows VM

**Always use `make vm`.** The test VM can only access `test-output/vm/`, so
the Windows binary MUST be built there — never to the repo root. The output
path is baked into the Makefile so no session has to remember it:

```bash
make vm        # -> test-output/vm/safe.exe (creates the dir if needed)
```

Do NOT run `go build -o safe.exe ./cmd/safe` directly — that drops the binary
in the repo root where the VM cannot reach it. `make check` runs the standard
pre-handoff combo: `go build ./...`, `go vet ./...`, then `make vm`.

### Test on VM checklist

For TUI changes: walk through all three options, verify rendering,
confirm no regressions.

For collection changes: run real collection, verify artifacts, run
`safe --verify`, check case_report.txt.

For analyzer changes: run `safe --analyze`, verify lab_report/ outputs,
check analyzer_result.json.

### Git workflow

```bash
git status                  # always check before any commit
git diff <file>             # review changes before staging
git add <specific files>    # never `git add .` carelessly
git commit -m "scope: clear description"
git push
git log --oneline -5        # confirm push landed
```

**Commit message style:** `scope: imperative description`

**Never rebase or force-push without explicit approval.** Salah has
declined rebase due to risk.

---

## Architecture Map

### Directory structure

```
safe/
├── cmd/safe/main.go
├── internal/
│   ├── analyzer/                # Lab-side parsing
│   ├── casemeta/                # Case metadata
│   ├── engine/                  # Profile orchestration
│   ├── manifest/                # SHA-256 manifests
│   ├── module/                  # Collection modules
│   ├── pathfinder/              # Profile discovery
│   ├── preflight/               # Environment checks
│   ├── profile/                 # Profile definitions
│   ├── tui/                     # Bubbletea TUI
│   └── vss/                     # Volume Shadow Copy
├── docs/
│   ├── PLAN.md
│   ├── PROFILES.md
│   ├── LIMITATIONS.md
│   ├── MODULES_REFERENCE.md
│   ├── DESIGN_QUESTIONS.md
│   ├── SESSION_HANDOFF.md
│   ├── MIGRATION_PLAN.md
│   ├── ROADMAP.md
│   └── journal/                 # Per-session journals
├── CLAUDE.md
├── README.md
├── CHANGELOG.md
└── go.mod
```

### Key dependencies

- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/charmbracelet/bubbles` — filepicker, viewport
- `github.com/charmbracelet/lipgloss` — styling
- `www.velocidex.com/golang/regparser` — registry parsing (analyzer)
- `www.velocidex.com/golang/go-prefetch` — Prefetch parsing (analyzer)

### Profile status

- **rapid_triage** (v0.2.0) — BUILT (9 modules)
- **endpoint_deep** (v0.3.0) — BUILT (rapid_triage superset + process_memory_inspection + extended_persistence + extended_event_channels)
- **memory_triage** (v0.1.0) — BUILT (dedicated LOUD profile: process_snapshot + process_memory_inspection)
- **domain_controller** — PLANNED (Phase 9)
- **server_role** — PLANNED (Phase 9)

12 collection modules built; 2 analyzer parsers (UserAssist, Prefetch).

### Phase status

- **Phase 1** — COMPLETE
- **Phase 2** (Extended Collection) — collection work COMPLETE (2026-06-12f):
  all three modules built + VM-verified. Deferred lab-side items (process_memory
  analyzer, COM-hijack parser, WMI surfacing) carry into Phase 4.
- **Phase 3** (Browser + Per-User) — NEXT collection phase
- **Phases 4-12** — PLANNED (see docs/PLAN.md)

---

## Known Issues and Tensions

### Antivirus false positives

Microsoft Defender ML flags safe.exe as false positives — seen so far:
"Program:Win32/Contebrew.A!ml" (Settings Modifier) and, after the
extended_persistence module, "Trojan:Win32/Bearfoos.A!ml" (Severe; the
persistence-enumeration behavior escalates the ML verdict). Both are false
positives from legitimate forensic behavior; flagged runs still complete
and verify cleanly. Documented in `docs/LIMITATIONS.md`. Mitigation: AV
exclusion on VM. Code signing planned for Phase 12.

**Do NOT** upload safe.exe (or its source/hashes) to VirusTotal or any
external scanner. See the "Operational Security — No External Publication"
rule above; this is a hard rule, not a preference.

### Plain Windows PowerShell rendering

TUI report viewer uses unicode characters that don't render in plain
PowerShell — they show as `?`. Pending fix in Session M1.

**Salah uses plain Windows PowerShell**, not Windows Terminal. Design
and test accordingly.

### Duplicate commit history

Commits `6457ef9` and `565b23b` are duplicates from a double-commit
mistake. Salah declined to rebase. They stay.

**Do NOT** suggest rebase to clean these up.

### No unit tests

No automated tests. VM testing is the integration suite.

---

## Open Design Questions

See `docs/DESIGN_QUESTIONS.md` for the full list. When working in areas
touched by a question there, read it first to avoid re-litigating
decisions.

---

## What This Project Is NOT

- Not a disk imager (use FTK Imager)
- Not a memory dumper (use winpmem or DumpIt)
- Not a malware analysis tool
- Not a SIEM
- Not a multi-platform tool (Windows only, by design)
- Not a network IDS

SAFE captures live and recently-accessible Windows host evidence
quickly and verifiably. It complements other tools rather than replacing
them.
