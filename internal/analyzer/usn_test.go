package analyzer

import "testing"

// TestFormatReasonCoverage locks the expanded USN reason decoding: reasons that
// the old five-flag whitelist dropped entirely (a lone DATA_OVERWRITE, a CLOSE)
// now decode, unknown bits are preserved rather than discarded, and an empty
// reason still yields "" so genuinely empty records are skipped.
func TestFormatReasonCoverage(t *testing.T) {
	cases := []struct {
		reason uint32
		want   string
	}{
		{0, ""},
		{0x00000001, "DATA_OVERWRITE"},                 // previously dropped
		{0x80000000, "CLOSE"},                          // previously dropped
		{0x00000800, "SECURITY_CHANGE"},                // previously dropped
		{0x00100000, "REPARSE_POINT_CHANGE"},           // previously dropped
		{0x00000100 | 0x80000000, "FILE_CREATE|CLOSE"}, // known bits, stable order
		{0x00002000 | 0x00001000, "RENAME_OLD_NAME|RENAME_NEW_NAME"},
		{0x08000000, "UNKNOWN(0x8000000)"}, // undefined bit preserved, not lost
	}
	for _, c := range cases {
		if got := formatReason(c.reason); got != c.want {
			t.Errorf("formatReason(0x%X) = %q, want %q", c.reason, got, c.want)
		}
	}
}
