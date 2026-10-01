package analyzer

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"
)

// TestProcessMemoryNotDumpedRWXStaysHigh proves that a region the collector
// could not dump (or whose blob can't be re-read) still keeps the RWX-private
// injection signal: it must triage HIGH with is_rwx=true from the protection
// metadata alone, not be flattened to LOW. A non-RWX not-dumped region stays LOW.
func TestProcessMemoryNotDumpedRWXStaysHigh(t *testing.T) {
	caseDir := t.TempDir()
	labDir := t.TempDir()
	modDir := filepath.Join(caseDir, "modules", "00_process_memory_inspection")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	regionsCSV := "pid,name,base_addr,region_size,state,protect,type,bytes,blob_path,dumped,note\n" +
		"1000,evil.exe,0x1000,4096,MEM_COMMIT,RWX,Private,0,,false,\n" +
		"1001,normal.exe,0x2000,4096,MEM_COMMIT,RW,Private,0,,false,\n"
	if err := os.WriteFile(filepath.Join(modDir, "regions.csv"), []byte(regionsCSV), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, errs := (&ProcessMemoryParser{}).Parse(caseDir, labDir, nil); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	rows := readCSV(t, filepath.Join(labDir, "process_memory", "regions_triage.csv"))
	hdr := rows[0]
	col := func(name string) int {
		for i, h := range hdr {
			if h == name {
				return i
			}
		}
		t.Fatalf("column %q not found in %v", name, hdr)
		return -1
	}
	pidCol, tierCol, rwxCol := col("pid"), col("triage_tier"), col("is_rwx")

	got := map[string][2]string{}
	for _, r := range rows[1:] {
		got[r[pidCol]] = [2]string{r[tierCol], r[rwxCol]}
	}
	if v := got["1000"]; v[0] != "HIGH" || v[1] != "true" {
		t.Errorf("RWX not-dumped region: got tier=%q is_rwx=%q, want HIGH/true", v[0], v[1])
	}
	if v := got["1001"]; v[0] != "LOW" || v[1] != "false" {
		t.Errorf("RW not-dumped region: got tier=%q is_rwx=%q, want LOW/false", v[0], v[1])
	}
}

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
