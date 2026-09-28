package html_report

import (
	"database/sql"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/Salahalza/SAFE/internal/evidence"
)

//go:embed index.html
var indexHTML []byte

type Server struct {
	caseDir      string
	labReportDir string
	port         int
	db           *sql.DB
	eventTypes   []string
	eventSources []string
	ftsRequested bool // --fts / SAFE_FTS: build & use the trigram FTS index
	ftsEnabled   bool // the trigram FTS index built OK; free-text search can use MATCH
	artifacts    *artifactLRU // parsed artifact CSVs, cached for paged/sorted/filtered serving
	rowCounts    *rowCountCache // per-file data-row counts, cached for the Explorer sidebar badges
	verify       *verifyState   // integrity-verification outcome, computed async on startup
	mu           sync.RWMutex
}

type TimelineEvent struct {
	Date       string `json:"date"`
	Time       string `json:"time"`
	Timezone   string `json:"timezone"`
	MACB       string `json:"macb"`
	Source     string `json:"source"`
	SourceType string `json:"sourcetype"`
	Type       string `json:"type"`
	User       string `json:"user"`
	Host       string `json:"host"`
	Short      string `json:"short"`
	Desc       string `json:"desc"`
	Version    string `json:"version"`
	Filename   string `json:"filename"`
	Inode      string `json:"inode"`
	Notes      string `json:"notes"`
	Format     string `json:"format"`
	Extra      string `json:"extra"`
}

type Tag struct {
	ID        string `json:"id"`
	EventData string `json:"event_data"`
	Note      string `json:"note"`
}

func StartServer(caseDir string, port int, enableFTS bool) error {
	s := &Server{
		caseDir:      caseDir,
		labReportDir: filepath.Join(caseDir, "lab_report"),
		port:         port,
		ftsRequested: enableFTS,
		artifacts:    newArtifactLRU(3),
		rowCounts:    newRowCountCache(),
		verify:       newVerifyState(),
	}

	fmt.Println("=========================================")
	fmt.Println("   SAFE HTML Report Server Starting      ")
	fmt.Println("=========================================")
	fmt.Printf("Case Directory: %s\n", caseDir)
	if enableFTS {
		fmt.Println("Free-text search: trigram FTS index enabled (first serve builds it; larger timeline.db)")
	}

	fmt.Print("Loading supertimeline into SQLite... ")
	start := time.Now()
	if err := s.loadTimeline(); err != nil {
		fmt.Printf("\n[!] Warning: failed to load timeline: %v (Timeline view will be empty)\n", err)
	} else {
		fmt.Printf("Done (%s)\n", time.Since(start).Round(time.Millisecond))
	}

	// Verify the evidence integrity in the background so the report loads
	// immediately; the header chip polls /api/verify and shows "Verifying…"
	// until this finishes. Launched after the timeline cache is built so the
	// derived timeline.db is settled before the reconciliation walk.
	fmt.Println("Verifying evidence integrity in the background (see the report header chip)...")
	go s.runVerify()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/case", s.handleCaseJSON)
	mux.HandleFunc("/api/result", s.handleResultJSON)
	mux.HandleFunc("/api/analyzer-result", s.handleAnalyzerResultJSON)
	mux.HandleFunc("/api/behavior-hits", s.handleBehaviorHits)
	mux.HandleFunc("/api/timeline", s.handleTimelineAPI)
	mux.HandleFunc("/api/artifact-files", s.handleArtifactFiles)
	mux.HandleFunc("/api/artifact-data", s.handleArtifactData)
	mux.HandleFunc("/api/webfile", s.handleWebFile)
	mux.HandleFunc("/api/tags", s.handleTagsAPI)
	mux.HandleFunc("/api/verify", s.handleVerify)
	mux.HandleFunc("/api/search", s.handleSearch)

	serverAddr := fmt.Sprintf("localhost:%d", port)
	fmt.Printf("\nServer running at: http://%s\n", serverAddr)
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println("=========================================")

	go func() {
		time.Sleep(500 * time.Millisecond) // Give server a moment to bind
		openBrowser("http://" + serverAddr)
	}()

	return http.ListenAndServe(serverAddr, mux)
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		fmt.Printf("Could not auto-open browser: %v\n", err)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(indexHTML)
}

func (s *Server) handleCaseJSON(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.caseDir, "case.json")
	s.serveFileJSON(w, path)
}

func (s *Server) handleResultJSON(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.caseDir, "result.json")
	s.serveFileJSON(w, path)
}

func (s *Server) handleAnalyzerResultJSON(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.labReportDir, "analyzer_result.json")
	s.serveFileJSON(w, path)
}

func (s *Server) serveFileJSON(w http.ResponseWriter, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "file not found"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleBehaviorHits(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.labReportDir, "behavior_hits.csv")
	f, err := os.Open(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
		return
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "failed to read CSV header")
		return
	}

	colRuleID := getColIndex(header, "rule_id")
	colSeverity := getColIndex(header, "severity")
	colMITRE := getColIndex(header, "mitre_technique")
	colTitle := getColIndex(header, "title")
	colSource := getColIndex(header, "evidence_source")
	colDetail := getColIndex(header, "evidence_detail")
	colTimelineSearchKey := getColIndex(header, "timeline_search_key")

	var hits []map[string]string
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		hit := make(map[string]string)
		if colRuleID != -1 && colRuleID < len(row) {
			hit["rule_id"] = row[colRuleID]
		}
		if colSeverity != -1 && colSeverity < len(row) {
			hit["severity"] = row[colSeverity]
		}
		if colMITRE != -1 && colMITRE < len(row) {
			hit["mitre_technique"] = row[colMITRE]
		}
		if colTitle != -1 && colTitle < len(row) { hit["title"] = row[colTitle] }
		if colSource != -1 && colSource < len(row) { hit["evidence_source"] = row[colSource] }
		if colDetail != -1 && colDetail < len(row) { hit["evidence_detail"] = row[colDetail] }
		if colTimelineSearchKey != -1 && colTimelineSearchKey < len(row) { hit["timeline_search_key"] = row[colTimelineSearchKey] }

		hits = append(hits, hit)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(hits)
}

func (s *Server) loadTimeline() error {
	dbPath := filepath.Join(s.labReportDir, "timeline.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	s.db = db

	// Create table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS timeline (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date TEXT,
			time TEXT,
			timezone TEXT,
			macb TEXT,
			source TEXT,
			sourcetype TEXT,
			type TEXT,
			user TEXT,
			host TEXT,
			short TEXT,
			desc TEXT,
			version TEXT,
			filename TEXT,
			inode TEXT,
			notes TEXT,
			format TEXT,
			extra TEXT
		);
	`)
	if err != nil {
		return err
	}

	// Check if already populated
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM timeline").Scan(&count)
	if err == nil && count > 0 {
		// A db built before indexing was added still lands here; ensure the
		// indexes exist so --serve on an already-analyzed case benefits without
		// a re-analyze. Idempotent: a no-op once the indexes are present.
		if err := ensureTimelineIndexes(db); err != nil {
			return err
		}
		if s.ftsRequested {
			s.ftsEnabled = ensureTimelineFTS(db)
		}
		return s.loadMetadata()
	}

	// Read CSV and insert
	csvPath := filepath.Join(s.labReportDir, "timeline.csv")
	f, err := os.Open(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return err
	}

	colIdx := make(map[string]int)
	for i, colName := range header {
		colIdx[strings.ToLower(colName)] = i
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO timeline (date, time, timezone, macb, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		getVal := func(name string) string {
			idx, exists := colIdx[name]
			if !exists || idx >= len(row) {
				return ""
			}
			return row[idx]
		}
		
		// datetime from csv is e.g. "2026-06-19 21:30:12.000000" or similar. We split it if it exists as 'datetime'
		dt := getVal("datetime")
		var dateStr, timeStr string
		if dt != "" {
			parts := strings.SplitN(dt, " ", 2)
			if len(parts) == 2 {
				dateStr = parts[0]
				timeStr = parts[1]
			} else {
				dateStr = getVal("date")
				timeStr = getVal("time")
			}
		} else {
			dateStr = getVal("date")
			timeStr = getVal("time")
		}

		_, err = stmt.Exec(
			dateStr, timeStr, getVal("timezone"), getVal("macb"), getVal("source"),
			getVal("sourcetype"), getVal("type"), getVal("user"), getVal("host"),
			getVal("short"), getVal("desc"), getVal("version"), getVal("filename"),
			getVal("inode"), getVal("notes"), getVal("format"), getVal("extra"),
		)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	_ = tx.Commit()

	// Index after the bulk insert (creating indexes up front would slow every
	// INSERT). Persisted in the db file, so subsequent loads reuse them.
	if err := ensureTimelineIndexes(db); err != nil {
		return err
	}
	if s.ftsRequested {
		s.ftsEnabled = ensureTimelineFTS(db)
	}

	return s.loadMetadata()
}

// ftsColumns are the timeline columns the free-text search box covers — the
// same set the old 12-way LIKE scan used. Kept in one place so the FTS schema
// and the LIKE fallback stay in sync.
var ftsColumns = []string{"date", "time", "source", "sourcetype", "type", "user", "host", "short", "desc", "filename", "notes", "extra"}

// ensureTimelineFTS builds a trigram-tokenized FTS5 index over the searchable
// timeline columns so the free-text search is a fast MATCH instead of a 12-way
// LIKE '%q%' full-table scan. Trigram is chosen over the default tokenizer
// specifically to preserve substring matching (an analyst pastes a path or hash
// fragment) — it indexes every 3-character sequence, so MATCH finds a substring
// anywhere in a value, case-insensitively, for query terms of 3+ characters.
//
// It is an external-content table (content='timeline'): the index stores only
// the trigram postings, not a second copy of the text, and 'rebuild' repopulates
// it from the timeline table. The timeline is immutable once built, so no sync
// triggers are needed. Idempotent — creates the vtable if absent and only
// rebuilds when empty — so it upgrades a db built before FTS existed on the next
// serve. Returns false (search falls back to LIKE) if anything fails, since FTS5
// availability depends on the SQLite build.
func ensureTimelineFTS(db *sql.DB) bool {
	// Detect an already-built index by the virtual table's existence, not by a
	// row count: on an external-content FTS5 table `SELECT count(*)` returns the
	// CONTENT table's row count, not the number of indexed entries, so it can
	// never be used to tell "created but not yet populated" from "populated".
	var existing string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='timeline_fts'`).Scan(&existing)
	if err == nil {
		return true // built by a previous load; reuse it
	}
	if err != sql.ErrNoRows {
		fmt.Fprintf(os.Stderr, "timeline FTS5 probe failed, search will use LIKE: %v\n", err)
		return false
	}

	// Create and populate the index in one transaction. The virtual table's mere
	// existence is what a later serve keys off (see the probe above), so the
	// CREATE and the 'rebuild' that populates it must be atomic: if they were
	// separate statements and the process were killed between them (a big case
	// spends ~45 s here), the next serve would find a committed-but-empty table,
	// reuse it, and silently return zero search results forever. A transaction
	// rolls the CREATE back on any failure or crash, so the build simply retries.
	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "timeline FTS5 unavailable, search will use LIKE: %v\n", err)
		return false
	}
	create := fmt.Sprintf(
		`CREATE VIRTUAL TABLE timeline_fts USING fts5(%s, content='timeline', content_rowid='id', tokenize='trigram')`,
		strings.Join(ftsColumns, ", "),
	)
	if _, err := tx.Exec(create); err != nil {
		_ = tx.Rollback()
		fmt.Fprintf(os.Stderr, "timeline FTS5 unavailable, search will use LIKE: %v\n", err)
		return false
	}
	// 'rebuild' populates the index from the content table in one pass.
	if _, err := tx.Exec(`INSERT INTO timeline_fts(timeline_fts) VALUES('rebuild')`); err != nil {
		_ = tx.Rollback()
		fmt.Fprintf(os.Stderr, "timeline FTS5 build failed, search will use LIKE: %v\n", err)
		return false
	}
	if err := tx.Commit(); err != nil {
		fmt.Fprintf(os.Stderr, "timeline FTS5 commit failed, search will use LIKE: %v\n", err)
		return false
	}
	return true
}

// ftsMatchArg wraps a user query as a trigram FTS5 phrase: double-quoted so the
// whole string is matched as one contiguous substring and its characters are not
// parsed as FTS5 query operators, with embedded double quotes doubled to escape.
func ftsMatchArg(q string) string {
	return `"` + strings.ReplaceAll(q, `"`, `""`) + `"`
}

// ensureTimelineIndexes creates the query indexes the report relies on, if they
// are not already present. Idempotent (CREATE INDEX IF NOT EXISTS), so it is
// safe to call on both a freshly-populated db and one built before indexing
// existed — the latter gets upgraded once, then every call is a no-op.
//   - (date, time): the report pages the timeline with ORDER BY date, time on
//     every request; the composite index lets SQLite return rows in order
//     instead of sorting the whole 500k–1M-row table each page.
//   - type / source: the Detections/Explorer filters query type = ? and
//     source = ?, and startup runs SELECT DISTINCT type/source for the filter
//     menus — both become index scans instead of full-table scans.
func ensureTimelineIndexes(db *sql.DB) error {
	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS idx_timeline_date_time ON timeline(date, time)`,
		`CREATE INDEX IF NOT EXISTS idx_timeline_type ON timeline(type)`,
		`CREATE INDEX IF NOT EXISTS idx_timeline_source ON timeline(source)`,
	} {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("create timeline index: %w", err)
		}
	}
	return nil
}

func (s *Server) loadMetadata() error {
	rows, err := s.db.Query("SELECT DISTINCT type FROM timeline WHERE type != ''")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err == nil {
			s.eventTypes = append(s.eventTypes, t)
		}
	}

	rows2, err := s.db.Query("SELECT DISTINCT source FROM timeline WHERE source != ''")
	if err != nil {
		return err
	}
	defer rows2.Close()
	for rows2.Next() {
		var src string
		if err := rows2.Scan(&src); err == nil {
			s.eventSources = append(s.eventSources, src)
		}
	}
	return nil
}

func (s *Server) handleTimelineAPI(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := r.URL.Query().Get("q")
	typeFilter := r.URL.Query().Get("type")
	sourceFilter := r.URL.Query().Get("source")
	macbFilter := r.URL.Query().Get("macb")
	startFilter := r.URL.Query().Get("start")
	endFilter := r.URL.Query().Get("end")
	sortDir := r.URL.Query().Get("sort")

	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}

	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
		if limit > 1000 {
			limit = 1000
		}
	}

	query := "SELECT date, time, timezone, macb, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra FROM timeline WHERE 1=1"
	var args []interface{}

	if typeFilter != "" {
		query += " AND type = ?"
		args = append(args, typeFilter)
	}
	if sourceFilter != "" {
		query += " AND source = ?"
		args = append(args, sourceFilter)
	}
	if macbFilter != "" {
		query += " AND ("
		for i, char := range macbFilter {
			if i > 0 {
				query += " OR "
			}
			query += "macb LIKE ?"
			args = append(args, "%"+string(char)+"%")
		}
		query += ")"
	}

	if startFilter != "" {
		startComp := startFilter
		if len(startComp) == 16 {
			startComp += ":00"
		}
		query += " AND (date || 'T' || time) >= ?"
		args = append(args, startComp)
	}
	if endFilter != "" {
		endComp := endFilter
		if len(endComp) == 16 {
			endComp += ":59"
		}
		query += " AND (date || 'T' || time) <= ?"
		args = append(args, endComp)
	}

	if q != "" {
		// Trigram FTS5 indexes 3-char sequences, so it can only answer terms of
		// 3+ characters; a 1–2 char term still needs the LIKE scan. Fall back to
		// LIKE too if the FTS index isn't available on this db.
		if s.ftsEnabled && len([]rune(q)) >= 3 {
			query += " AND id IN (SELECT rowid FROM timeline_fts WHERE timeline_fts MATCH ?)"
			args = append(args, ftsMatchArg(q))
		} else {
			query += " AND (date LIKE ? OR time LIKE ? OR source LIKE ? OR sourcetype LIKE ? OR type LIKE ? OR user LIKE ? OR host LIKE ? OR short LIKE ? OR desc LIKE ? OR filename LIKE ? OR notes LIKE ? OR extra LIKE ?)"
			likeQ := "%" + q + "%"
			for i := 0; i < 12; i++ {
				args = append(args, likeQ)
			}
		}
	}

	// Get total count
	countQuery := strings.Replace(query, "SELECT date, time, timezone, macb, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra", "SELECT COUNT(*)", 1)
	var total int
	_ = s.db.QueryRow(countQuery, args...).Scan(&total)

	// Add order and limit. Default to newest-first: on a real case an ascending
	// timeline opens on decades-old file-system/ShimCache timestamps, burying the
	// incident; descending also floats the behavioral ALERT rows (written with a
	// 9999-12-31 sentinel) to the very top. Ascending stays available via ?sort=asc.
	order := "DESC"
	if sortDir == "asc" {
		order = "ASC"
	}
	query += " ORDER BY date " + order + ", time " + order + " LIMIT ? OFFSET ?"
	args = append(args, limit, (page-1)*limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer rows.Close()

	var events []TimelineEvent
	for rows.Next() {
		var ev TimelineEvent
		if err := rows.Scan(
			&ev.Date, &ev.Time, &ev.Timezone, &ev.MACB, &ev.Source, &ev.SourceType, &ev.Type,
			&ev.User, &ev.Host, &ev.Short, &ev.Desc, &ev.Version, &ev.Filename,
			&ev.Inode, &ev.Notes, &ev.Format, &ev.Extra,
		); err == nil {
			events = append(events, ev)
		}
	}

	if events == nil {
		events = []TimelineEvent{}
	}

	response := map[string]any{
		"events":        events,
		"total":         total,
		"page":          page,
		"limit":         limit,
		"event_types":   s.eventTypes,
		"event_sources": s.eventSources,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleArtifactFiles(w http.ResponseWriter, r *http.Request) {
	caser := cases.Title(language.English)

	// One walked CSV, before counting. Keep the absolute path so the row count
	// reads the real file, and the folder/rel already resolved for the response.
	type walkedFile struct {
		folder string
		rel    string
		abs    string
	}
	var found []walkedFile

	err := filepath.Walk(s.labReportDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".csv") {
			return nil
		}
		rel, rerr := filepath.Rel(s.labReportDir, path)
		if rerr != nil || rel == "timeline.csv" || rel == "behavior_hits.csv" || strings.HasSuffix(rel, "timeline.db") {
			return nil
		}
		folder := filepath.Dir(rel)
		if folder == "." {
			if strings.HasPrefix(rel, "mft_") {
				folder = "File System"
			} else {
				folder = "Root"
			}
		} else {
			folder = strings.ReplaceAll(folder, "_", " ")
			folder = caser.String(folder)
		}
		if strings.ToLower(folder) == "mft" {
			folder = "File System"
		}
		found = append(found, walkedFile{folder: folder, rel: filepath.ToSlash(rel), abs: path})
		return nil
	})

	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "failed to scan artifact files")
		return
	}

	// Row counts drive the per-file signal badges and the EVTX high-value
	// ordering. Count concurrently so the first sidebar open on a case with a
	// multi-hundred-MB IIS log or MFT doesn't stall; the count cache makes every
	// later open of the same, unchanged case instant.
	counts := make([]int, len(found))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range found {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if fi, serr := os.Stat(found[i].abs); serr == nil {
				counts[i] = s.rowCounts.count(found[i].abs, fi.ModTime())
			}
		}(i)
	}
	wg.Wait()

	filesByFolder := make(map[string][]artifactFile)
	for i, wf := range found {
		filesByFolder[wf.folder] = append(filesByFolder[wf.folder], artifactFile{Path: wf.rel, Rows: counts[i]})
	}
	for folder, files := range filesByFolder {
		orderArtifactFiles(folder, files)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(filesByFolder)
}

// handleWebFile serves the CONTENT of a collected IIS web-root script so the
// analyst can read the actual shell source in the browser. The `path` query is
// the web_files.csv relative_path (e.g. "1/ForUploadFiles/AspxSpy2014Final.aspx").
// The file is read from the per-module encrypted payload container
// (evidence.ContainerName) when present, or a legacy loose web/ tree (raw or
// .qtn) for older cases — either way the browser gets the real, decoded source,
// not the AV-inert bytes on disk. Content is capped for display; the true hash
// lives in web_files.csv.
func (s *Server) handleWebFile(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	if rel == "" || strings.Contains(rel, "..") {
		s.respondWithError(w, http.StatusBadRequest, "invalid path")
		return
	}

	modDirs, _ := filepath.Glob(filepath.Join(s.caseDir, "modules", "*_iis_collection"))
	if len(modDirs) == 0 {
		s.respondWithError(w, http.StatusNotFound, "no IIS web collection in this case")
		return
	}
	modDir := modDirs[0]

	var data []byte
	encoded := false

	containerPath := filepath.Join(modDir, evidence.ContainerName)
	if evidence.ContainerExists(containerPath) {
		// Current format: extract the single raw entry from the encrypted container.
		// The lookup is an exact entry-name match, so `rel` never touches the disk.
		b, rerr := evidence.ReadContainerEntry(containerPath, filepath.ToSlash(rel))
		if rerr != nil {
			s.respondWithError(w, http.StatusNotFound, "web file not found")
			return
		}
		data = b
		encoded = true
	} else {
		// Legacy format: loose web/ tree (raw or .qtn-transformed files).
		base := filepath.Join(modDir, "web")
		cand := filepath.Clean(filepath.Join(base, filepath.FromSlash(rel)))
		if _, err := os.Stat(cand); err != nil {
			if _, err2 := os.Stat(cand + evidence.EncodedSuffix); err2 == nil {
				cand += evidence.EncodedSuffix
			} else {
				s.respondWithError(w, http.StatusNotFound, "web file not found")
				return
			}
		}
		// Bound the resolved path to the web root (defence in depth vs. traversal).
		absBase, _ := filepath.Abs(base)
		absCand, _ := filepath.Abs(cand)
		if !strings.HasPrefix(absCand, absBase) {
			s.respondWithError(w, http.StatusBadRequest, "path out of bounds")
			return
		}
		b, rerr := os.ReadFile(cand)
		if rerr != nil {
			s.respondWithError(w, http.StatusInternalServerError, "failed to read web file")
			return
		}
		if evidence.IsEncoded(cand) {
			evidence.Transform(b, 0) // decode the quarantine-safe transform
			encoded = true
		}
		data = b
	}

	const displayCap = 1 << 20 // 1 MiB is plenty for a shell; bound the payload
	fullSize := len(data)
	truncated := false
	if len(data) > displayCap {
		data = data[:displayCap]
		truncated = true
	}

	resp := map[string]any{
		"path":      filepath.ToSlash(rel),
		"encoded":   encoded,
		"size":      fullSize,
		"truncated": truncated,
		"content":   string(data),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleTagsAPI(w http.ResponseWriter, r *http.Request) {
	tagsFile := filepath.Join(s.caseDir, "tags.json")

	if r.Method == http.MethodGet {
		data, err := os.ReadFile(tagsFile)
		if err != nil {
			if os.IsNotExist(err) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[]`))
				return
			}
			s.respondWithError(w, http.StatusInternalServerError, "failed to read tags")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	if r.Method == http.MethodPost {
		var tags []Tag
		if err := json.NewDecoder(r.Body).Decode(&tags); err != nil {
			s.respondWithError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		data, err := json.MarshalIndent(tags, "", "  ")
		if err != nil {
			s.respondWithError(w, http.StatusInternalServerError, "failed to encode tags")
			return
		}
		if err := os.WriteFile(tagsFile, data, 0644); err != nil {
			s.respondWithError(w, http.StatusInternalServerError, "failed to write tags")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
		return
	}

	s.respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (s *Server) respondWithError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error": %q}`, message)))
}

func getColIndex(header []string, name string) int {
	name = strings.ToLower(name)
	for i, col := range header {
		if strings.ToLower(col) == name {
			return i
		}
	}
	return -1
}
