package module

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

// interpretivePhrases are strings the old queryRunKey wrote into the evidence
// file — tool commentary and provenance that must never contaminate the raw
// command artifact. The collected file must be exactly what reg emitted.
var interpretivePhrases = []string{
	"RESULT:",
	"This is normal",
	"found unused at collection time",
	"Query: reg query",
	"Raw output:",
	"KEY NOT FOUND",
	"KEY EMPTY",
	"KEY HAS VALUES",
}

func assertNoInterpretation(t *testing.T, content string) {
	t.Helper()
	for _, p := range interpretivePhrases {
		if strings.Contains(content, p) {
			t.Errorf("evidence content contains interpretive text %q; it must be raw reg output only:\n%s", p, content)
		}
	}
}

// TestQueryRunKeyRawOutput runs the real reg query path on the Windows host and
// confirms the returned content is the raw command output (no injected commentary)
// while the missing/present classification is reported via the state return.
func TestQueryRunKeyRawOutput(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("queryRunKey shells out to reg.exe; Windows only")
	}

	// A key that exists on every Windows host.
	present := `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
	state, content, err := queryRunKey(context.Background(), present)
	if err != nil {
		t.Fatalf("unexpected error querying %s: %v", present, err)
	}
	if state == runKeyMissing {
		t.Fatalf("expected %s to exist, got runKeyMissing", present)
	}
	assertNoInterpretation(t, content)
	if !strings.Contains(strings.ToUpper(content), "HKEY_LOCAL_MACHINE") {
		t.Errorf("expected raw reg output to include the key path, got:\n%s", content)
	}

	// A key that does not exist: reg exits non-zero, which must be classified as
	// missing (nil err) with the raw "unable to find" text — no commentary.
	absent := `HKLM\Software\Microsoft\Windows\CurrentVersion\SAFE_NONEXISTENT_TEST_KEY_ZZZ`
	state, content, err = queryRunKey(context.Background(), absent)
	if err != nil {
		t.Fatalf("a missing key must not be an error, got: %v", err)
	}
	if state != runKeyMissing {
		t.Fatalf("expected runKeyMissing for %s, got state %d", absent, state)
	}
	assertNoInterpretation(t, content)
}
