package roles

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// buildImageRoot copies a collected SYSTEM hive into a temp image-root layout
// (Windows\System32\config\SYSTEM) so the offline *Image detectors can run over it.
func buildImageRoot(t *testing.T, hive string) string {
	t.Helper()
	root := t.TempDir()
	dst := filepath.Join(root, "Windows", "System32", "config")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(hive)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(filepath.Join(dst, "SYSTEM"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
	return root
}

func glob(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

// TestIsDomainControllerImageMissingHive confirms graceful handling: a root with
// no SYSTEM hive is simply "not a DC", never a panic. Always runs.
func TestIsDomainControllerImageMissingHive(t *testing.T) {
	if IsDomainControllerImage(t.TempDir()) {
		t.Error("empty root should not be detected as a domain controller")
	}
}

// TestIsDomainControllerImageRealHives exercises the Select\Current control-set
// resolution against real collected SYSTEM hives when they are present under
// test-output (that evidence set is gitignored, so this skips in a clean
// checkout). A DC's hive (collected by ad_collection) must be detected; a non-DC
// server hive (collected by registry_core on the IIS image) must not.
func TestIsDomainControllerImageRealHives(t *testing.T) {
	repo := filepath.Join("..", "..")
	dcHives := glob(filepath.Join(repo, "test-output", "vm", "*", "modules", "*_ad_collection", "SYSTEM"))
	nonDCHives := glob(filepath.Join(repo, "test-output", "container-validation", "*", "modules", "*_registry_core", "HKLM_SYSTEM.hiv"))
	if len(dcHives) == 0 && len(nonDCHives) == 0 {
		t.Skip("no collected SYSTEM hives under test-output; skipping real-hive role detection")
	}

	if len(dcHives) > 0 {
		detected := 0
		for _, h := range dcHives {
			if IsDomainControllerImage(buildImageRoot(t, h)) {
				detected++
			}
		}
		if detected == 0 {
			t.Errorf("no DC hive among %d ad_collection SYSTEM hives was detected as a domain controller", len(dcHives))
		}
	}

	for _, h := range nonDCHives {
		if IsDomainControllerImage(buildImageRoot(t, h)) {
			t.Errorf("non-DC server hive %s was misdetected as a domain controller", h)
		}
	}
}
