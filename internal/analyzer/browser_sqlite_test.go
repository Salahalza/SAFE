package analyzer

import "testing"

// TestFileURIImmutable locks in the read-only/immutable file: URI form so a
// collected browser DB is opened without SQLite writing -wal/-shm sidecars into
// the evidence directory. Inputs are forward-slash absolute paths (what
// immutableSQLiteDSN passes in after resolving/ToSlash), so the expectation is
// stable across OSes.
func TestFileURIImmutable(t *testing.T) {
	cases := map[string]string{
		"C:/Users/a/places.sqlite":         "file:///C:/Users/a/places.sqlite?immutable=1",
		"C:/Users/a b/Local Settings/x.db": "file:///C:/Users/a%20b/Local%20Settings/x.db?immutable=1",
		"/home/u/f.db":                     "file:///home/u/f.db?immutable=1",
	}
	for in, want := range cases {
		if got := fileURIImmutable(in); got != want {
			t.Errorf("fileURIImmutable(%q) = %q, want %q", in, got, want)
		}
	}
}
