package evidence

import (
	"bytes"
	"path/filepath"
	"sort"
	"testing"
)

// TestContainerRoundTrip proves the per-case payload container stores and returns
// entries byte-for-byte — including arbitrary binary content, the sharpest test of
// requirement (a) — and that entry enumeration and single-entry lookup both work.
func TestContainerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ContainerName)

	// A range of payloads: text, empty, and all 256 byte values (binary).
	full := make([]byte, 256)
	for i := range full {
		full[i] = byte(i)
	}
	want := map[string][]byte{
		"1/uploads/shell.aspx": []byte(`<% Process.Start("cmd") %>`),
		"1/empty.asp":          {},
		"2/bin.php":            full,
	}

	cw, err := NewContainerWriter(path)
	if err != nil {
		t.Fatalf("NewContainerWriter: %v", err)
	}
	for name, data := range want {
		if err := cw.Add(name, data); err != nil {
			t.Fatalf("Add %s: %v", name, err)
		}
	}
	if cw.Count() != len(want) {
		t.Errorf("Count = %d, want %d", cw.Count(), len(want))
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !ContainerExists(path) {
		t.Fatalf("ContainerExists = false after write")
	}

	// Enumerate: every entry comes back with identical bytes.
	got := map[string][]byte{}
	if err := ReadContainer(path, func(name string, data []byte) error {
		got[name] = append([]byte(nil), data...)
		return nil
	}); err != nil {
		t.Fatalf("ReadContainer: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d entries, want %d", len(got), len(want))
	}
	for name, w := range want {
		if !bytes.Equal(got[name], w) {
			t.Errorf("entry %s: bytes differ (got %d, want %d)", name, len(got[name]), len(w))
		}
	}

	// Single-entry lookup: hit and miss.
	b, err := ReadContainerEntry(path, "2/bin.php")
	if err != nil {
		t.Fatalf("ReadContainerEntry: %v", err)
	}
	if !bytes.Equal(b, full) {
		t.Errorf("ReadContainerEntry bytes differ")
	}
	if _, err := ReadContainerEntry(path, "does/not/exist"); err == nil {
		t.Errorf("ReadContainerEntry(missing) = nil error, want not-exist")
	}

	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	t.Logf("entries: %v", names)
}
