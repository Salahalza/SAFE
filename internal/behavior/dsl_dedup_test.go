package behavior

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDisableThenReEnableNoDuplicate proves that disabling a rule id and then
// re-registering the same id (here within one rules list; the same happens
// across two overlay files) yields exactly one rule, not two. Before the fix the
// id lingered in the ordering slice after the disable-delete, so the re-enable
// appended it a second time and the rule was emitted — and evaluated — twice,
// doubling every hit it produced.
func TestDisableThenReEnableNoDuplicate(t *testing.T) {
	rulesDir := t.TempDir()
	os.WriteFile(filepath.Join(rulesDir, "dup.yml"), []byte(`
rules:
  - id: DUP-TEST
    title: first
    severity: INFO
    source: x.csv
    match:
      field: a
      equals: "1"
    evidence: "e"
  - id: DUP-TEST
    title: disabled
    severity: INFO
    source: x.csv
    enabled: false
  - id: DUP-TEST
    title: re-enabled
    severity: HIGH
    source: x.csv
    match:
      field: a
      equals: "1"
    evidence: "e"
`), 0o644)

	rules, _ := loadDeclRules(rulesDir)
	count := 0
	for _, r := range rules {
		if r.ID() == "DUP-TEST" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("DUP-TEST appears %d times in the loaded rule set, want 1", count)
	}
}
