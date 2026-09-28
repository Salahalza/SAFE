package hashutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Known SHA-256 of "abc".
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	got, err := SHA256File(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("SHA256File = %q, want %q", got, want)
	}

	if _, err := SHA256File(filepath.Join(dir, "nope")); err == nil {
		t.Error("expected an error for a missing file")
	}
}
