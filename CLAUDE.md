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

**Current name in code:** SAHM (System for Artifact Harvesting and Management)

**Target name (planned rename):** SAFE (System for Artifacts Forensic and Examination)

**Rename status:** Deliberate future task. Not started. See
`docs/SESSION_HANDOFF.md` for the migration plan.

**Naming exploration history (condensed):**
We considered ATHAR (أثر, "trace"), BASMA (بصمة, "fingerprint"),
FAHS (فحص, "examination"), SAYF (سيف, "sword"), and SWORD before
landing on SAFE. The rename has not been executed because the
collision concern (a Saudi stocks app uses "SAHM") does not block
internal development. Re-litigating the name is not useful.

---

## Project Purpose

SAHM/SAFE is a Windows forensic acquisition tool written in Go, designed
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

## Architectural Principles (DO NOT VIOLATE)

These are not preferences — they are load-bearing decisions for the project.
Violating them breaks the design. Each was decided deliberately after debate.

### 1. Strict collection/analysis separation

**Rule:** Modules in `internal/module/` collect files. They do NOT parse,
analyze, or interpret data on the target device.

**Why:** Every command run on a target adds noise to event logs, may
trigger EDR, and risks interaction with malware that watches for forensic
activity. SAHM/SAFE is a "quiet visitor."

**Where parsing happens:** `internal/analyzer/` packages, run via
`sahm --analyze <case-folder>` in the analyst's lab environment.

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

```bash
GOOS=windows GOARCH=amd64 go build -o sahm.exe ./cmd/sahm
```

### Test on VM checklist

For TUI changes: walk through all three options, verify rendering,
confirm no regressions.

For collection changes: run real collection, verify artifacts, run
`sahm --verify`, check case_report.txt.

For analyzer changes: run `sahm --analyze`, verify lab_report/ outputs,
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
sahm/
├── cmd/sahm/main.go
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

- **rapid_triage** (v0.2.0) — BUILT
- **endpoint_deep** — PLANNED (Phase 2)
- **domain_controller** — PLANNED (Phase 9)
- **server_role** — PLANNED (Phase 9)

### Phase status

- **Phase 1** — COMPLETE
- **Phase 2** — NEXT
- **Phases 3-12** — PLANNED (see docs/PLAN.md)

---

## Known Issues and Tensions

### Antivirus false positives

Microsoft Defender ML flags sahm.exe as "Program:Win32/Contebrew.A!ml"
(category: Settings Modifier). False positive from legitimate forensic
behavior. Documented in `docs/LIMITATIONS.md`. Mitigation: AV exclusion
on VM. Code signing planned for Phase 12.

**Do NOT** upload sahm.exe to VirusTotal. Salah declined this.

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

SAHM/SAFE captures live and recently-accessible Windows host evidence
quickly and verifiably. It complements other tools rather than replacing
them.
