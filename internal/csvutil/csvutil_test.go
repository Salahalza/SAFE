package csvutil

import "testing"

func TestCsvSafe(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"normal.exe", "normal.exe"},
		{"=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"},
		{"+SUM(A1)", "'+SUM(A1)"},
		{"-2+3", "'-2+3"},
		{"@echo", "'@echo"},
		{"\ttabbed", "'\ttabbed"},
		{"\rcarriage", "'\rcarriage"},
		{"'already-quoted", "'already-quoted"}, // leading quote left as-is (idempotent)
		{"C:\\Windows\\system32", "C:\\Windows\\system32"},
	}
	for _, c := range cases {
		if got := CsvSafe(c.in); got != c.want {
			t.Errorf("CsvSafe(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Re-applying must be a no-op on already-quoted danger values.
	once := CsvSafe("=danger")
	if twice := CsvSafe(once); twice != once {
		t.Errorf("CsvSafe not idempotent: %q -> %q", once, twice)
	}
}
