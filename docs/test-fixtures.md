# Test Fixtures

Reference case folders used to verify SAFE's lab-side analyzers against known
inputs with known-good outputs. Because real artifacts (registry hives, memory
dumps) are large binary blobs, the fixtures themselves are **kept locally and
are NOT committed to git** (`test-fixtures/` is gitignored, same as
`test-output/`). This file documents what each fixture proves and exactly how
to regenerate it, so the binary data can be rebuilt on the VM at any time.

> Why not commit the hives? The `com_hijack` fixture alone is ~109 MB (the HKLM
> SOFTWARE hive is ~85 MB). Committing that permanently bloats repo history for
> a single-developer private repo. The recipe below is the source of truth; the
> binary fixture is a local convenience.

---

## `test-fixtures/com_hijack_planted/`

**Proves:** the `com_hijack` analyzer detects a real COM-hijack (MITRE
T1546.015) — a per-user CLSID that shadows a machine-wide HKLM CLSID with a
different module path — and tiers the weaker scriptlet / LOLBin signals as
NOTABLE, while leaving legitimate per-user COM (OneDrive) at NOTABLE, never
HIGH.

**Contents (lean subset of a real `rapid_triage` collection):**

```
modules/05_registry_core/HKLM_SOFTWARE.hiv     # the shadow oracle (~85 MB)
modules/08_user_hives_collection/<sid>/UsrClass.dat   # per-user CLSID surface
lab_report/com_hijack/                          # the proven-good output
```

**How it was planted (Windows 11 VM, elevated).** The hijacks were written into
an *offline* user's `UsrClass.dat` via `reg load` / `reg unload` so the keys are
flushed to disk immediately — avoiding the lazy-flush race that makes a live
`reg add` + immediate collection miss the keys. Replace the username with a
non-logged-on local account:

```powershell
reg load HKLM\Tmp "C:\Users\<OFFLINE_USER>\AppData\Local\Microsoft\Windows\UsrClass.dat"

# (A) HIGH: shadows the real HKLM ShellLink CLSID with a Temp path
reg add "HKLM\Tmp\CLSID\{00021401-0000-0000-C000-000000000046}\InprocServer32" /ve /d "C:\Temp\evil.dll" /f
reg add "HKLM\Tmp\CLSID\{00021401-0000-0000-C000-000000000046}\InprocServer32" /v ThreadingModel /d Apartment /f
# (B) NOTABLE: scriptlet server module
reg add "HKLM\Tmp\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32" /ve /d "C:\Temp\payload.sct" /f
# (C) NOTABLE: LOLBin server command
reg add "HKLM\Tmp\CLSID\{99999999-8888-7777-6666-555555555555}\LocalServer32" /ve /d "mshta.exe C:\Temp\x.hta" /f

reg unload HKLM\Tmp     # flushes to disk

# then collect (rapid_triage is enough — it has registry_core + user_hives_collection)
.\safe.exe
```

Cleanup: `reg load HKLM\Tmp "...UsrClass.dat"`, `reg delete` the three CLSID
keys, `reg unload HKLM\Tmp`.

**Expected analyzer output** (`lab_report/com_hijack/`):

| CLSID | tier | why |
| --- | --- | --- |
| `{00021401-…}` → `C:\Temp\evil.dll` | **HIGH** | `shadows_hklm=true, hklm_path_differs=true` — overrides the real ShellLink server (`windows.storage.dll`) |
| `{11111111-…}` → `payload.sct` | NOTABLE | `script/scriptlet server module (.sct)` |
| `{99999999-…}` → `mshta.exe …` | NOTABLE | `LOLBin in server command (mshta)` |

Plus the host's real OneDrive CLSIDs as NOTABLE (`server in user-writable path
(appdata)`) — none HIGH. Stats: `servers_high=1`.

**How to re-run the regression (no VM needed — the analyzer is platform-
independent Go):**

```bash
TMP=$(mktemp -d)/regression
cp -R test-fixtures/com_hijack_planted/modules "$TMP/"
go run ./cmd/safe --analyze "$TMP"
# expect: com_hijack SUCCESS, servers_high=1, the {00021401-…} -> C:\Temp\evil.dll HIGH row
```

---

## Adding fixtures

When a future analyzer needs a known-input regression case, capture the minimal
module subset it parses (not the whole 160 MB case), drop it under
`test-fixtures/<name>/`, and document here: what it proves, how it was produced,
and the expected output. Keep the binary data local; keep the recipe in git.
