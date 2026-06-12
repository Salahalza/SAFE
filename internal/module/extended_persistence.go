package module

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ExtendedPersistence struct{}

func (m *ExtendedPersistence) Name() string              { return "extended_persistence" }
func (m *ExtendedPersistence) Priority() Priority        { return PriorityNormal }
func (m *ExtendedPersistence) TimeBudget() time.Duration { return 5 * time.Minute }
func (m *ExtendedPersistence) RequiresVSS() bool         { return false }

// Run captures readable `reg query` snapshots of extended Auto-Start Extensibility
// Points (ASEPs) that persistence_core does not already cover: BAM/DAM execution
// evidence, the full service registry tree, and a set of lower-profile autostart
// and credential-persistence locations attackers favour.
//
// Relationship to other modules — important context:
//
//   - registry_core already `reg save`s the full HKLM\SYSTEM and HKLM\SOFTWARE
//     hives, and user_hives_collection saves every NTUSER.DAT. So the RAW data
//     behind every key below is already collected. This module does not collect
//     anything new; it provides human-readable, point-in-time text snapshots for
//     fast triage — the same deliberate overlap persistence_core accepts, and
//     the same pattern as extended_event_channels vs. eventlogs_core.
//
//   - The query output IS the artifact (principle #1 exception: a single native
//     command as the collection method, no on-target analysis).
//
// COM hijacks are intentionally NOT dumped here. Machine-wide HKLM\…\CLSID is
// enormous, and per-user CLSID hijacks live in each user's NTUSER.DAT — which an
// on-target `reg query HKCU` cannot reach (it only sees the account SAFE runs
// under). COM is therefore left to a lab-side parser of the already-collected
// SOFTWARE and NTUSER hives; a finding records this so it isn't mistaken for a
// gap.
//
// Missing/empty keys are normal for many of these mechanisms (e.g. AppCertDlls,
// Browser Helper Objects, DAM on workstations). queryRunKey — reused from
// persistence_core — classifies those as info findings rather than errors, so a
// clean host does not produce a degraded status.
func (m *ExtendedPersistence) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Findings:   []Finding{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	// Each entry is queried recursively (reg query <key> /s) and written as a
	// readable text snapshot. Ordered by mechanism for analyst readability.
	aseps := []struct {
		filename string
		key      string
	}{
		// BAM/DAM — per-user last-execution evidence (program names + timestamps).
		{"bam_user_settings.txt", `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`},
		{"bam_user_settings_legacy.txt", `HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings`},
		{"dam_user_settings.txt", `HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings`},

		// Service definitions — ImagePath, ServiceDll (svchost services), Start
		// type, and FailureCommand are all hijack/persistence vectors not visible
		// in persistence_core's live `sc query` output.
		{"services_registry.txt", `HKLM\SYSTEM\CurrentControlSet\Services`},

		// Credential / authentication persistence.
		{"lsa.txt", `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`},
		{"security_providers.txt", `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders`},

		// Native / boot-time execution: BootExecute, KnownDLLs, AppCertDlls,
		// SafeDllSearchMode all live under Session Manager.
		{"session_manager.txt", `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`},

		// DLL load-order and helper-DLL persistence.
		{"netsh_helpers.txt", `HKLM\SOFTWARE\Microsoft\Netsh`},
		{"print_monitors.txt", `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`},
		{"time_providers.txt", `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders`},

		// Logon / shell / session autostart.
		{"winlogon_full.txt", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`},
		{"active_setup.txt", `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`},
		{"shell_extensions_approved.txt", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`},
		{"browser_helper_objects.txt", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`},
		{"browser_helper_objects_wow64.txt", `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`},
	}

	missing, empty := 0, 0
	for _, a := range aseps {
		outPath := filepath.Join(ctx.OutputDir, a.filename)

		state, content, err := queryRunKey(ctx.Ctx, a.key)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("query %s: %v", a.filename, err))
			continue
		}

		if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("write %s: %v", a.filename, err))
			continue
		}

		artifact, err := describeArtifact(outPath)
		if err != nil {
			result.AddWarning(a.filename, fmt.Sprintf("hash failed: %v", err))
			continue
		}
		result.Artifacts = append(result.Artifacts, artifact)

		switch state {
		case runKeyMissing:
			missing++
			result.AddInfo(a.filename, "key does not exist on this target")
		case runKeyEmpty:
			empty++
			result.AddInfo(a.filename, "key exists but contains no values")
		}
	}

	result.AddInfo("extended_persistence",
		fmt.Sprintf("queried %d extended persistence locations: %d present with values, %d empty, %d absent",
			len(aseps), len(aseps)-missing-empty, empty, missing))

	// Record why COM is not dumped here, so the absence reads as a decision.
	result.AddInfo("com_hijacks",
		"COM object registrations (HKLM Classes\\CLSID and per-user NTUSER Classes) are collected as raw hives by registry_core and user_hives_collection; surfacing COM hijacks is deferred to a lab-side hive parser, since per-user CLSID is not reachable via on-target reg query")

	finalize(&result, started, ctx.Ctx)
	return result
}
