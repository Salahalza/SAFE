package analyzer

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeUTF16LE writes s as UTF-16LE into buf at off (ASCII-only helper for tests).
func writeUTF16LE(buf []byte, off int, s string) {
	for i, r := range s {
		binary.LittleEndian.PutUint16(buf[off+i*2:], uint16(r))
	}
}

// buildValidMFTRecord builds a 1024-byte record with a STANDARD_INFORMATION and
// a FILE_NAME attribute naming the given file, so the parser extracts a row.
func buildValidMFTRecord(name string) []byte {
	buf := make([]byte, 1024)
	copy(buf, "FILE")
	binary.LittleEndian.PutUint16(buf[20:], 56) // first attribute offset

	// STANDARD_INFORMATION (0x10) at 56, length 96, content offset 24.
	binary.LittleEndian.PutUint32(buf[56:], 0x10)
	binary.LittleEndian.PutUint32(buf[60:], 96)
	binary.LittleEndian.PutUint16(buf[76:], 24)
	// A non-zero creation FILETIME so the row carries a timestamp.
	binary.LittleEndian.PutUint64(buf[80:], 130000000000000000)

	// FILE_NAME (0x30) at 152, length 120, content offset 24.
	binary.LittleEndian.PutUint32(buf[152:], 0x30)
	binary.LittleEndian.PutUint32(buf[156:], 120)
	binary.LittleEndian.PutUint16(buf[172:], 24)
	coff := 152 + 24
	buf[coff+64] = byte(len(name)) // name length in UTF-16 chars
	writeUTF16LE(buf, coff+66, name)

	// Attribute terminator at 272.
	binary.LittleEndian.PutUint32(buf[272:], 0xFFFFFFFF)
	return buf
}

// buildOOBMFTRecord builds a record whose only attribute sits near the end of the
// buffer with a short length, so a STANDARD_INFORMATION content-offset read would
// run past the 1024-byte record and panic if unguarded.
func buildOOBMFTRecord() []byte {
	buf := make([]byte, 1024)
	copy(buf, "FILE")
	binary.LittleEndian.PutUint16(buf[20:], 1004) // first attribute offset near the end
	binary.LittleEndian.PutUint32(buf[1004:], 0x10)
	binary.LittleEndian.PutUint32(buf[1008:], 4) // passes the attrOffset+attrLen guard, but +20..22 is OOB
	return buf
}

func writeTestMFT(t *testing.T, records ...[]byte) (caseDir, labDir string) {
	t.Helper()
	caseDir = t.TempDir()
	labDir = t.TempDir()
	modDir := filepath.Join(caseDir, "modules", "00_ntfs_metadata")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for _, r := range records {
		raw = append(raw, r...)
	}
	if err := os.WriteFile(filepath.Join(modDir, "MFT"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return caseDir, labDir
}

// TestMFTParseOOBRecordNoPanic proves a crafted record that would previously
// read past the record buffer no longer panics (which, since parsers run as
// unrecovered goroutines, would abort the entire analyze run) and that a valid
// record in the same file is still parsed.
func TestMFTParseOOBRecordNoPanic(t *testing.T) {
	caseDir, labDir := writeTestMFT(t, buildValidMFTRecord("test.exe"), buildOOBMFTRecord())

	outputs, stats, errs := (&MFTParser{}).Parse(caseDir, labDir, nil)
	if len(errs) != 0 {
		t.Fatalf("clean EOF should surface no errors, got: %v", errs)
	}
	if stats["records_processed"] != 2 {
		t.Fatalf("expected 2 records processed, got %v", stats["records_processed"])
	}
	if len(outputs) == 0 {
		t.Fatal("expected output files")
	}

	data, err := os.ReadFile(filepath.Join(labDir, "mft_full.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "test.exe") {
		t.Fatalf("valid record's filename missing from mft_full.csv:\n%s", data)
	}
}
