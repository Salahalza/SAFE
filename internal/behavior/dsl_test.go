package behavior

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCSV writes a header + rows to path, creating parent dirs.
func writeCSV(t *testing.T, path string, header []string, rows [][]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write(header)
	for _, r := range rows {
		_ = w.Write(r)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
}

// TestDefaultsLoadClean confirms every embedded default parses and validates
// (no warnings) and that the expected rule IDs are present.
func TestDefaultsLoadClean(t *testing.T) {
	rules, warnings := loadDeclRules("")
	if len(warnings) != 0 {
		t.Fatalf("embedded defaults produced warnings: %v", warnings)
	}
	got := map[string]bool{}
	for _, r := range rules {
		got[r.ID()] = true
	}
	want := []string{"B-01", "B-02", "B-03", "B-04", "B-05", "B-06", "B-07", "B-08", "B-09", "B-10", "B-11", "T2-11", "T2-12"}
	for _, id := range want {
		if !got[id] {
			t.Errorf("expected default rule %s to be loaded", id)
		}
	}
	if len(rules) != len(want) {
		t.Errorf("expected %d default rules, got %d", len(want), len(rules))
	}
}

// TestDefaultRuleMatching drives the ported rules over synthetic evidence and
// locks the tricky exclusion logic that was carried over from the Go versions.
func TestDefaultRuleMatching(t *testing.T) {
	dir := t.TempDir()

	writeCSV(t, filepath.Join(dir, "evtx", "Security.csv"),
		[]string{"event_id", "event_data"},
		[][]string{
			{"4624", `{"LogonType":10,"IpAddress":"8.8.8.8"}`},        // B-08 fires (external RDP)
			{"4624", `{"LogonType":10,"IpAddress":"127.0.0.1"}`},      // B-08 excluded (loopback)
			{"4624", `{"LogonType":3,"IpAddress":"8.8.8.8"}`},         // B-08 no (not RDP)
			{"4720", `{"TargetUserName":"evil"}`},                     // B-07 fires
			{"4688", `{"TokenElevationType":"%%1937"}`},               // B-06 fires
			{"4688", `{"CommandLine":"vssadmin delete shadows /all"}`},// T2-12 fires
			{"4688", `{"CommandLine":"vssadmin delete shadows /shadow={GUID} /quiet"}`}, // T2-12 excluded (targeted)
			{"1102", `{}`},                                            // T2-11 fires
		})

	// *Defender* glob source.
	writeCSV(t, filepath.Join(dir, "evtx", "Microsoft-Windows-Windows-Defender-Operational.csv"),
		[]string{"event_id", "event_data"},
		[][]string{
			{"5007", "Value DisableRealtimeMonitoring changed to 1"}, // B-05 fires (protection-disabling key)
			{"5007", "Value SignatureUpdateInterval changed"},        // B-05 excluded (benign bookkeeping)
			{"5001", "Realtime protection disabled"},                 // B-05 fires (5001 always)
		})

	hits, err := Run(dir, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	count := map[string]int{}
	for _, h := range hits {
		count[h.RuleID]++
	}

	want := map[string]int{
		"B-05":  2,
		"B-06":  1,
		"B-07":  1,
		"B-08":  1,
		"T2-11": 1,
		"T2-12": 1,
	}
	for id, n := range want {
		if count[id] != n {
			t.Errorf("rule %s: expected %d hits, got %d", id, n, count[id])
		}
	}
}

// TestSeverityFromColumn checks the tier-driven severity path (B-01 style):
// HIGH/NOTABLE rows emit at that severity, other tiers are skipped.
func TestSeverityFromColumn(t *testing.T) {
	dir := t.TempDir()
	writeCSV(t, filepath.Join(dir, "scheduled_tasks", "tasks.csv"),
		[]string{"tier", "task_name", "command", "arguments", "flags"},
		[][]string{
			{"HIGH", "evil", "powershell.exe", "-enc AAAA", "LOLBin"},
			{"NOTABLE", "meh", "rundll32.exe", "", "LOLBin"},
			{"LOW", "fine", "notepad.exe", "", ""},
		})

	rules, _ := loadDeclRules("")
	var b01 Rule
	for _, r := range rules {
		if r.ID() == "B-01" {
			b01 = r
		}
	}
	if b01 == nil {
		t.Fatal("B-01 not loaded")
	}
	hits := b01.Evaluate(dir)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits (HIGH+NOTABLE, LOW skipped), got %d", len(hits))
	}
	if hits[0].Severity != SeverityHigh || hits[1].Severity != SeverityNotable {
		t.Errorf("severity not taken from tier column: %+v", hits)
	}
	if hits[0].EvidenceSource != "scheduled_tasks/tasks.csv" {
		t.Errorf("unexpected evidence source: %q", hits[0].EvidenceSource)
	}
}

// TestExternalOverlay covers the external-file semantics: adding a new rule,
// overriding a built-in by id, disabling a built-in with enabled:false, and
// skipping a malformed file without aborting.
func TestExternalOverlay(t *testing.T) {
	rulesDir := t.TempDir()

	// New custom rule.
	os.WriteFile(filepath.Join(rulesDir, "custom.yml"), []byte(`
id: CUSTOM-01
title: Custom Rule
mitre: T1000
severity: HIGH
source: custom/thing.csv
match:
  field: bad
  equals: yes
evidence: "custom {bad}"
`), 0o644)

	// Override B-07's title, and disable B-08.
	os.WriteFile(filepath.Join(rulesDir, "overrides.yml"), []byte(`
rules:
  - id: B-07
    title: Overridden Account Rule
    mitre: T1136.001
    severity: HIGH
    source: evtx/Security.csv
    match:
      field: event_id
      equals: "4720"
    evidence: "x"
  - id: B-08
    title: disabled
    severity: INFO
    source: evtx/Security.csv
    enabled: false
`), 0o644)

	// Malformed file — must be skipped, not fatal.
	os.WriteFile(filepath.Join(rulesDir, "broken.yml"), []byte("id: BAD\nmatch: [this is not valid: {{{"), 0o644)

	rules, warnings := loadDeclRules(rulesDir)
	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID()] = r
	}

	if byID["CUSTOM-01"] == nil {
		t.Error("custom rule not loaded")
	}
	if byID["B-07"] == nil || byID["B-07"].Name() != "Overridden Account Rule" {
		t.Errorf("B-07 override not applied: %v", byID["B-07"])
	}
	if byID["B-08"] != nil {
		t.Error("B-08 should have been disabled by enabled:false")
	}
	// A warning should mention the broken file.
	sawBroken := false
	for _, w := range warnings {
		if strings.Contains(w, "broken.yml") {
			sawBroken = true
		}
	}
	if !sawBroken {
		t.Errorf("expected a warning about broken.yml, got: %v", warnings)
	}
}
