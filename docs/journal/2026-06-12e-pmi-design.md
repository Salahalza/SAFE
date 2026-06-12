# Session Journal: 2026-06-12e

## Goal

Run the quiet-visitor design debate for `process_memory_inspection` and lock
a principle-preserving design. Design only — no code.

## What got done

- Held the PMI design debate and resolved it to a **collect-only** design
  (details under "What got decided"). No code this session — design only.
- Wrote this design journal.
- Corrected documentation drift:
  - `LIMITATIONS.md` — rewrote the present-tense text that described PMI as a
    shipped feature ("SAFE v1.0 includes per-process memory inspection") into
    honest "planned, collect-only" framing; added the PMI-is-loudest /
    may-be-EDR-blocked note.
  - `DESIGN_QUESTIONS.md` — appended a 2026-06-12 follow-up to the 2026-05-27
    Memory Acquisition entry recording the collect-only refinement, region
    filter, and profile placement (original entry left intact as history).
  - `ROADMAP.md` — updated the Tracking-section format **example** to point at
    this journal's filename (see surprise below — it was an example, not a
    stale checkbox).

All changes this session are documentation. No functional code, no VM test
needed.

## What got decided

- **Build-vs-buy stays settled.** The 2026-05-27 decision (Option 4: native
  user-mode PMI, no WinPmem, no kernel driver) is NOT reopened. The debate was
  only about how PMI squares with two load-bearing principles.
- **Collect-only PMI.** On-target, the module dumps raw region bytes plus
  region metadata and makes **zero interpretation**. All judgment — strings,
  PE-carve, RWX classification, suspicious-region summary — moves to a new
  lab-side `process_memory` analyzer. This preserves Principle #1 (collection
  ≠ analysis) and makes findings reproducible instead of one-shot on a hostile
  host. Fits Principle #1's "the bytes ARE the artifact" exception, like the
  event-channel `.evtx` copies.
- **Region filter default: committed + private (non-image/non-mapped) +
  executable-or-RWX protection.** This is a protection-flag *scope filter*
  (collection scoping, like "only `.evtx` files"), not content interpretation.
  Targets injected / unbacked code — the IR-relevant ~80%. Image-backed code is
  excluded because it is recoverable from disk. This is the size/loudness knob.
- **Profile placement: both.** A new dedicated loud profile `memory_triage`
  (`process_snapshot` + `process_memory_inspection`, v0.1.0) AND composed into
  `endpoint_deep` (→ v0.3.0, description gains an EDR-visible warning). Never in
  `rapid_triage`. Cheap because PMI is one module referenced by two profiles;
  the only added cost is defining the second profile.
- **Status semantics.** `success` if enumeration ran and ≥1 process opened;
  `partial` if some/all `OpenProcess` calls were denied (the normal EDR/PPL/
  system case); `failed` only if enumeration itself failed. Per-process denials
  are info findings, not errors — mirrors `extended_persistence`'s absent-key
  handling. One warning finding states the module is EDR-visible and regions
  may have been blocked.
- **Order of volatility:** PMI runs right after `process_snapshot` (needs the
  PID list) and before any memory-perturbing module.
- **Module-integrity diffing is out of scope for this artifact set, honestly.**
  Integrity diffing needs image-backed regions, which the collect-only
  exec-private filter deliberately excludes. Not faked, not silently dropped —
  documented as a scope boundary.

## What got punted

Deferred to implementation (roadmap 2.2), flagged not silently dropped:

- Process-enumeration mechanism — match `process_snapshot`'s existing approach.
- Optional operator PID-allowlist "targeted mode" (default is attempt-all).
- Per-region / total byte cap to bound runaway output size.
- WOW64 / 32-bit address-space walking.
- The lab-side `process_memory` analyzer is its own implementation task.

All tracked here and in ROADMAP.md (2.2).

## What surprised us

- I over-flagged "doc drift." `ROADMAP.md:177` is an **example inside a format
  code-block** under `## Tracking`, not a real completion checkbox claiming 2.1
  was done with a phantom journal. I corrected my own claim mid-session;
  updated the example filename to this journal so it reads accurately, but it
  was never a stale task marker. The only genuine drift was `LIMITATIONS.md`
  describing PMI in the present tense as already shipped.
- The 2026-05-27 DESIGN_QUESTIONS "Next session" scope literally prescribed
  on-target RWX detection + strings extraction — i.e. analysis on the target.
  That entry predates the collection/analysis split being treated as
  load-bearing. Collect-only resolves the conflict it would otherwise have
  created.

## What's next

Implement PMI (roadmap 2.2): build the collection module first, VM-test
(`make vm` → `test-output/vm/safe.exe`), then build the lab `process_memory`
analyzer. This is functional code — VM verification required before any commit.

## Notes for the next session

- Don't re-litigate: collect-only, the exec/RWX-private region filter, the
  both-profiles placement, or build-vs-buy. All decided here / 2026-05-27.
- On-target PMI does NO interpretation. If implementation creeps toward RWX
  verdicts / strings / PE parsing on the target, that's a Principle #1
  violation — keep all of it in the lab analyzer.
- Expect Defender to escalate beyond Bearfoos and real EDR to possibly block or
  strip handles mid-read. `partial` status is the correct outcome, not a bug.
- PMI must never enter `rapid_triage`.
