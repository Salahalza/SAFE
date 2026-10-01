package csvutil

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadCSVHelperShortRowSkippedAndReported proves a row with fewer columns
// than the header is skipped (not passed to the callback) and that the skip is
// now reported to stderr instead of vanishing silently.
func TestReadCSVHelperShortRowSkippedAndReported(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "in.csv")
	content := "a,b,c\n1,2,3\nSHORT,ROW\n4,5,6\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Capture stderr.
	orig := os.Stderr
	rd, wr, _ := os.Pipe()
	os.Stderr = wr

	var seen [][]string
	err := ReadCSVHelper(p, func(header, row []string) error {
		seen = append(seen, append([]string(nil), row...))
		return nil
	})

	wr.Close()
	os.Stderr = orig
	out, _ := io.ReadAll(rd)

	if err != nil {
		t.Fatalf("ReadCSVHelper returned error: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("expected 2 well-formed rows to reach the callback, got %d: %v", len(seen), seen)
	}
	for _, r := range seen {
		if len(r) != 3 {
			t.Errorf("callback got a short row: %v", r)
		}
	}
	if !strings.Contains(string(out), "skipped 1 row") {
		t.Errorf("expected a stderr warning about the skipped short row, got: %q", string(out))
	}
}

// TestReadCSVHelperCleanFileSilent confirms a well-formed file emits no warning.
func TestReadCSVHelperCleanFileSilent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "clean.csv")
	if err := os.WriteFile(p, []byte("a,b\n1,2\n3,4\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := os.Stderr
	rd, wr, _ := os.Pipe()
	os.Stderr = wr

	_ = ReadCSVHelper(p, func(header, row []string) error { return nil })

	wr.Close()
	os.Stderr = orig
	out, _ := io.ReadAll(rd)
	if len(out) != 0 {
		t.Errorf("expected no stderr output for a clean file, got: %q", string(out))
	}
}
