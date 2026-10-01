package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseEvtxFileCorruptSurfacesError proves a corrupted / wrong-magic .evtx
// no longer parses as a silent "0 rows, no error" (which was indistinguishable
// from a channel that legitimately never fired, masking log tampering). A file
// with a readable-size header but the wrong magic makes evtx.GetChunks return an
// error, which parseEvtxFile must now surface.
func TestParseEvtxFileCorruptSurfacesError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.evtx")
	// 4096 zero bytes: large enough for the header struct, but the magic is not
	// "ElfFile\0", so GetChunks returns a wrong-magic error.
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}

	rows, chunkErrs, err := parseEvtxFile(p)
	if err == nil {
		t.Fatal("expected an error for a corrupt/wrong-magic evtx, got nil (silent 0 rows)")
	}
	if len(rows) != 0 || chunkErrs != 0 {
		t.Fatalf("expected no rows/chunk errors on a hard failure, got rows=%d chunkErrs=%d", len(rows), chunkErrs)
	}
}
