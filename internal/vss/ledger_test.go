package vss

import (
	"testing"
)

func TestShadowLedger(t *testing.T) {
	ledgerDir = t.TempDir()
	t.Cleanup(func() { ledgerDir = "" })

	if ids := ledgerShadowIDs(); len(ids) != 0 {
		t.Fatalf("fresh ledger should be empty, got %v", ids)
	}

	if err := recordShadowID("{AAA}"); err != nil {
		t.Fatal(err)
	}
	if err := recordShadowID("{BBB}"); err != nil {
		t.Fatal(err)
	}
	// Duplicate record must not produce a duplicate on read.
	if err := recordShadowID("{AAA}"); err != nil {
		t.Fatal(err)
	}

	ids := ledgerShadowIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 distinct IDs, got %v", ids)
	}

	unrecordShadowID("{AAA}")
	ids = ledgerShadowIDs()
	if len(ids) != 1 || ids[0] != "{BBB}" {
		t.Fatalf("after removing AAA expected [BBB], got %v", ids)
	}

	// Removing the last entry clears the ledger entirely.
	unrecordShadowID("{BBB}")
	if ids := ledgerShadowIDs(); len(ids) != 0 {
		t.Fatalf("ledger should be empty after removing all, got %v", ids)
	}
}

func TestExtractShadowID(t *testing.T) {
	out := "noise\nSHADOW_ID={12345678-90AB-CDEF-1234-567890ABCDEF}\nDEVICE_OBJECT=\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy9\n"
	if got := extractShadowID(out); got != "{12345678-90AB-CDEF-1234-567890ABCDEF}" {
		t.Errorf("extractShadowID = %q", got)
	}
	if got := extractShadowID("no id here"); got != "" {
		t.Errorf("expected empty for no match, got %q", got)
	}
}
