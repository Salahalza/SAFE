package analyzer

import (
	"database/sql"
	"net/url"
	"path/filepath"
	"strings"
)

// openCollectedSQLite opens a COLLECTED SQLite database (browser history,
// cookies, downloads) read-only and immutable, so analysis never mutates the
// evidence set.
//
// A plain read-write open of a WAL-mode database — SQLite's default for modern
// Firefox/Chromium — makes SQLite create `-wal` and `-shm` sidecar files next to
// the database the moment it is read. Those files land in the evidence module
// directory, are absent from the collection manifest, and so make a later
// `safe-analyze -verify` report them as tampering — besides the deeper problem
// that the analyzer has written into the preserved evidence folder at all.
//
// The `immutable=1` URI parameter tells SQLite the file sits on read-only media:
// it opens read-only and disables all locking, change detection, and the WAL, so
// no `-wal`/`-shm`/`-journal` file is ever created. modernc.org/sqlite always
// opens with SQLITE_OPEN_URI and passes a `file:` DSN through verbatim, so the URI
// parameter takes effect. This reads the committed contents of the main database
// file, which is the forensically correct view of a collected artifact.
//
// This is only for collected evidence DBs. The rebuildable timeline cache
// (`lab_report/timeline.db`) is derived output, not evidence, and is opened
// normally elsewhere.
func openCollectedSQLite(dbPath string) (*sql.DB, error) {
	return sql.Open("sqlite", immutableSQLiteDSN(dbPath))
}

// immutableSQLiteDSN builds a SQLite `file:` URI that opens dbPath immutable
// (read-only, no journal/WAL sidecars). dbPath is first resolved to an absolute
// path — collected DB paths are usually relative to the case folder, and a `file:`
// URI must be absolute — then expressed in the documented Windows form
// `file:///C:/dir/file.db`.
func immutableSQLiteDSN(dbPath string) string {
	if abs, err := filepath.Abs(dbPath); err == nil {
		dbPath = abs
	}
	return fileURIImmutable(filepath.ToSlash(dbPath))
}

// fileURIImmutable turns a forward-slash absolute path into an immutable SQLite
// file: URI, percent-encoding each segment so paths with spaces or reserved
// characters still parse, while preserving a leading drive-letter segment ("C:").
func fileURIImmutable(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // C:/dir/f.db -> /C:/dir/f.db
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if len(s) == 2 && s[1] == ':' {
			continue // preserve a drive-letter segment ("C:") literally
		}
		segs[i] = url.PathEscape(s)
	}
	return "file://" + strings.Join(segs, "/") + "?immutable=1"
}
