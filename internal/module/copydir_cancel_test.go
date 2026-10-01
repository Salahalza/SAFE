package module

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFiles(t *testing.T, dir string, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, "f"+string(rune('a'+i))+".bin")
		if err := os.WriteFile(p, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCopyDirHonorsCancellation proves the bulk-copy walk stops promptly when the
// module's context is cancelled (a large tree like SYSVOL must be able to unwind
// on a time-budget expiry) — and copies normally when it isn't. copyDir is the
// shared helper behind SYSVOL and the other bulk collectors, which all use the
// same ctx.Ctx.Err() guard.
func TestCopyDirHonorsCancellation(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	writeFiles(t, src, 5)

	// Cancelled context: copyDir must bail without copying and report the error.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	dstCancelled := t.TempDir()
	count, _, errs := copyDir(&Context{Ctx: cctx, OutputDir: dstCancelled}, src, dstCancelled)
	if count != 0 {
		t.Errorf("cancelled copyDir copied %d files, want 0", count)
	}
	if len(errs) == 0 {
		t.Error("cancelled copyDir returned no error; the cancellation was not surfaced")
	}

	// Healthy context: copyDir copies all files.
	dstOK := t.TempDir()
	count, _, errs = copyDir(&Context{Ctx: context.Background(), OutputDir: dstOK}, src, dstOK)
	if count != 5 {
		t.Errorf("healthy copyDir copied %d files, want 5 (errs: %v)", count, errs)
	}
}
