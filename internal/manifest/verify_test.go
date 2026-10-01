package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

// TestVerifyExcludesDerivedReportArtifacts proves -verify no longer flags the
// report server's derived, regenerable files (the timeline.db cache and its
// sidecars, and tags.json) as tampering, while still catching a genuinely
// planted file.
func TestVerifyExcludesDerivedReportArtifacts(t *testing.T) {
	caseDir := t.TempDir()
	labDir := filepath.Join(caseDir, "lab_report")
	if err := os.MkdirAll(labDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// One real evidence file, covered by the lab manifest.
	evPath := filepath.Join(labDir, "timeline.csv")
	if err := os.WriteFile(evPath, []byte("date,time\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := sha256File(evPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(labDir, "manifest.sha256"), []byte(h+"  timeline.csv\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Case manifest must exist for Verify; empty is fine here.
	if err := os.WriteFile(filepath.Join(caseDir, "manifest.sha256"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// Derived artifacts created by opening the report / tagging — must NOT flag.
	for name, content := range map[string]string{
		filepath.Join(labDir, "timeline.db"):     "db",
		filepath.Join(labDir, "timeline.db-wal"): "wal",
		filepath.Join(labDir, "timeline.db-shm"): "shm",
		filepath.Join(caseDir, "tags.json"):      "[]",
	} {
		if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := Verify(caseDir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("expected OK with derived artifacts present, got Extra=%v Missing=%v Mismatches=%v",
			res.Extra, res.Missing, res.Mismatches)
	}

	// A genuinely planted file must still fail verification.
	if err := os.WriteFile(filepath.Join(labDir, "planted.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res2, err := Verify(caseDir)
	if err != nil {
		t.Fatal(err)
	}
	if res2.OK {
		t.Fatal("expected a planted file to fail verification, but it passed")
	}
}
