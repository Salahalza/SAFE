package vss

import (
	"context"
	"os"
	"testing"
)

// TestLiveShadowLifecycleAndOrphanReclaim exercises the real VSS path end to end:
// a normal create/cleanup cycle, and — the point of the ledger — reclaiming a
// symlink-less orphan that the C:\safe_shadow_* glob can never find. It creates
// and deletes real Volume Shadow Copies, so it needs an ELEVATED session and is
// gated behind SAFE_VSS_LIVE_TEST=1 to stay out of ordinary `go test ./...` runs.
func TestLiveShadowLifecycleAndOrphanReclaim(t *testing.T) {
	if os.Getenv("SAFE_VSS_LIVE_TEST") != "1" {
		t.Skip("set SAFE_VSS_LIVE_TEST=1 (elevated Windows) to run the live VSS test")
	}
	// Isolate the ledger so the test never touches the machine-wide one.
	ledgerDir = t.TempDir()
	t.Cleanup(func() { ledgerDir = "" })

	// --- Normal lifecycle: create records the ID, Cleanup clears everything ---
	sh, err := CreateShadow("C:")
	if err != nil {
		t.Fatalf("CreateShadow: %v", err)
	}
	// Safety net: never leak the shadow if an assertion below fails.
	leaked := sh.ShadowID
	defer func() {
		if leaked != "" {
			_ = deleteShadow(context.Background(), leaked)
		}
	}()

	if ids := ledgerShadowIDs(); len(ids) != 1 || ids[0] != sh.ShadowID {
		t.Fatalf("ledger should hold the created ID %s, got %v", sh.ShadowID, ids)
	}
	if ok, _ := shadowExists(sh.ShadowID); !ok {
		t.Fatal("created shadow not found in WMI")
	}
	if _, err := os.Lstat(sh.MountedPath); err != nil {
		t.Fatalf("symlink %s missing: %v", sh.MountedPath, err)
	}

	if err := sh.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	leaked = ""
	if ok, _ := shadowExists(sh.ShadowID); ok {
		t.Error("shadow still exists after Cleanup")
	}
	if ids := ledgerShadowIDs(); len(ids) != 0 {
		t.Errorf("ledger not cleared after Cleanup: %v", ids)
	}

	// --- Symlink-less orphan reclaim (the R fix) ---
	sh2, err := CreateShadow("C:")
	if err != nil {
		t.Fatalf("CreateShadow #2: %v", err)
	}
	leaked = sh2.ShadowID
	// Simulate a crash/failure after Create: remove the symlink, leaving the
	// shadow and its ledger entry but nothing for the glob to find.
	if err := removeSymlink(sh2.MountedPath); err != nil {
		t.Fatalf("remove symlink to simulate orphan: %v", err)
	}
	if ids := ledgerShadowIDs(); len(ids) != 1 {
		t.Fatalf("ledger should still hold the orphan, got %v", ids)
	}

	cleaned, errs := CleanupOrphans()
	if len(errs) != 0 {
		t.Fatalf("CleanupOrphans errors: %v", errs)
	}
	if cleaned < 1 {
		t.Error("CleanupOrphans did not reclaim the symlink-less orphan")
	}
	if ok, _ := shadowExists(sh2.ShadowID); ok {
		t.Error("symlink-less orphan shadow still exists after CleanupOrphans")
	}
	leaked = ""
	if ids := ledgerShadowIDs(); len(ids) != 0 {
		t.Errorf("ledger not cleared after orphan reclaim: %v", ids)
	}
}
