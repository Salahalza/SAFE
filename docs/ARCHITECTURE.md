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

### 9. Collected artifacts are raw and tool-agnostic

**Rule:** The collection side outputs artifacts byte-for-byte as they exist
on the source volume. A collected file IS the source object — the `MFT`
output is the raw `$MFT` stream, a hive is the raw hive, a `.evtx` is the
raw log. The collection side never parses, normalizes, decodes, or reformats
an artifact into a SAFE-specific representation. All interpretation happens
on the analysis side.

**Why:** A SAFE case folder must be a neutral evidence set, not a
SAFE-only format. The analyst must be able to point any third-party tool
(MFTECmd, Timeline Explorer, X-Ways, plaso, EZ Tools) at the raw artifacts
and get exactly the bytes they would have pulled off the disk themselves.
SAFE's parsers are one consumer of that evidence, never the gatekeeper to
it. This also protects chain of custody: the collected object is the
original, hashed as-is (principle #5).

**Payload-class carve-out (the sole exception — and it stays raw):** A few
artifacts — attacker web shells in a site root — carry content the analyst's
own workstation AV recognizes and quarantines the instant SAFE writes the
collected copy. Storing them as loose raw files would let the host AV
destroy the evidence. The invariant is therefore that a payload-class
artifact must be stored in a form that is **(a) byte-for-byte recoverable by
any third-party tool** AND **(b) not quarantinable by the host AV on write.**
The mechanism is a per-module container (archive): the raw, unmodified file
lives inside it — extractable unchanged by any tool — while the container form
keeps on-access AV from quarantining it. No lossy or SAFE-proprietary
transform of the payload bytes.

**Implementation:** payload-class web-root scripts are stored raw inside one
per-module **ZipCrypto-encrypted zip** (`web_payloads.zip`, one per
`iis_collection` module) — see `internal/evidence/container.go`. Encryption is
required for (b): a *plain* zip does NOT satisfy it — Windows Defender inspects
inside an unencrypted archive and quarantines it; only an encrypted archive is
opaque to the scanner. The password is the fixed, non-secret malware-handling
convention **`infected`**, recorded here and in the code so any analyst — and
any third-party tool (7-Zip, Info-ZIP unzip, Python `zipfile`) — can extract
the raw evidence. The password is a container property, not a transform of the
payload bytes, so (a) holds: the stored bytes are the exact original. The
analyzer records each payload's *true* SHA-256 in `web_files.csv`; the manifest
hashes the container as one file (principle #4/#5).

**Validation:** the container mechanism is proven against a live Windows
Defender (real-time protection on, no exclusions) using the actual production
writer: a container built by `internal/evidence` and holding a known-detectable
payload (EICAR) scans **CLEAN** — Defender cannot see inside → not quarantinable
(b) — while 7-Zip extracts it byte-for-byte with the `infected` password, and a
unit test round-trips all 256 byte values through the writer/reader (a). The
legacy reversible `.qtn` transform in `codec.go` is retained **read-only** for
backward compatibility with cases collected before this migration.

**Read side — AV-safe on live too (was the last gap):** storing the payload in
an encrypted container protects the *write*, but the collector still has to
*read* the source bytes first. On a dead image that read goes through raw NTFS
(`internal/module/image_reader.go`, `ctx.Image`), which no on-access scanner can
gate. On a **live** host the read previously used an ordinary `os.ReadFile` from
the VSS shadow mount, on the (now-retired) assumption that a scanner would not
re-scan a read from the shadow — which is false: Defender's minifilter scans on
file-open by content, shadow or not. The live read now goes through the **same
raw-NTFS mechanism, pointed at the shadow device** (`NewRawVolumeReader` over
`Shadow.ShadowPath`, read by shadow-root-relative path — the exact technique
`ntfs_metadata` uses for `$MFT`); block I/O issues no per-file open, so there is
nothing for the scanner to gate. Set as `ctx.PayloadReader` by `iis_collection`
for the live payload phase; `readEvidenceBytes` honours it (falling back to
`os.ReadFile` only for a web root the shadow does not cover).

**Validated end-to-end on a live IIS host (EXCH01, Defender RTP on, no
exclusions):** (1) a clean collect reproduced the OS-read baseline **byte-for-byte**
— 814 stored web files, 732 analyzed script hashes identical to a prior
`os.ReadFile` collect of the same host, `-verify` clean; (2) a Defender-detectable
EICAR `.aspx` dropped in a live web root was **quarantined from the live volume by
Defender within ~20 s** (confirming a live `os.ReadFile` would fail), yet SAFE
**raw-read it out of the shadow into the container** — `1/eicar_test.aspx`, 68
bytes, container SHA-256 == the known EICAR hash == the analyzer's recorded hash,
Info-ZIP-extractable with `infected`, `-verify` clean; the host's own Defender
then instantly quarantined the *loose* extracted copy while never touching the
encrypted container. The full collect → extract → hash-match flow is confirmed on
genuine live evidence with AV active. No open items remain on principle #9.
