package html_report

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// artifactTable is a fully-parsed artifact CSV held in memory so that paging,
// sorting, and filtering over it never re-read a multi-hundred-MB file on every
// request. The largest artifacts in a real case (the raw MFT, an IIS request
// log) run to millions of rows; serving them a page at a time from a cached
// parse is what keeps the Artifact Explorer from loading the whole file into the
// browser (or re-reading it from disk per keystroke).
type artifactTable struct {
	headers []string
	rows    [][]string
	mtime   time.Time
}

// artifactLRU is a tiny, mtime-validated LRU of parsed artifact CSVs. Only a
// handful of files are ever open in the Explorer at once, so a small cap keeps a
// bounded amount of memory resident while making page/sort/filter instant after
// the first load. An entry is invalidated automatically if the file's mtime
// changes, so a re-analyze that rewrites a CSV is picked up on the next request.
type artifactLRU struct {
	mu    sync.Mutex
	cap   int
	items map[string]*artifactTable
	order []string // least-recently-used first
}

func newArtifactLRU(capacity int) *artifactLRU {
	if capacity < 1 {
		capacity = 1
	}
	return &artifactLRU{cap: capacity, items: make(map[string]*artifactTable)}
}

// touch moves key to the most-recently-used end. Caller holds the lock.
func (c *artifactLRU) touch(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, key)
}

// get returns the cached table for key only if it is present and its stored
// mtime matches the file's current mtime; otherwise nil (a re-parse is needed).
func (c *artifactLRU) get(key string, mtime time.Time) *artifactTable {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.items[key]
	if !ok || !t.mtime.Equal(mtime) {
		return nil
	}
	c.touch(key)
	return t
}

// put stores t under key and evicts the least-recently-used entries past the cap.
func (c *artifactLRU) put(key string, t *artifactTable) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = t
	c.touch(key)
	for len(c.order) > c.cap {
		evict := c.order[0]
		c.order = c.order[1:]
		delete(c.items, evict)
	}
}

// loadArtifactTable returns the parsed CSV at absPath, from cache when the file
// is unchanged since it was cached, otherwise by parsing it once and caching it.
func (s *Server) loadArtifactTable(absPath, key string) (*artifactTable, error) {
	fi, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}
	if t := s.artifacts.get(key, fi.ModTime()); t != nil {
		return t, nil
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	var rows [][]string
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		rows = append(rows, row)
	}

	t := &artifactTable{headers: header, rows: rows, mtime: fi.ModTime()}
	s.artifacts.put(key, t)
	return t, nil
}

// handleArtifactData serves one parsed artifact CSV a page at a time. Filtering
// (a case-insensitive substring match across all cells), sorting (by a column
// index, numeric when both cells parse as numbers), and an optional exact-value
// column filter (fcol/fvals, used by the "Shells only" quick filter) all happen
// server-side over the cached parse, so the browser only ever receives and
// renders one page — never the whole (potentially millions-of-rows) file.
func (s *Server) handleArtifactData(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	relPath := q.Get("path")
	if relPath == "" || strings.Contains(relPath, "..") {
		s.respondWithError(w, http.StatusBadRequest, "invalid path")
		return
	}

	path := filepath.Clean(filepath.Join(s.labReportDir, filepath.FromSlash(relPath)))
	if !strings.HasPrefix(path, s.labReportDir) {
		s.respondWithError(w, http.StatusBadRequest, "invalid path out of bounds")
		return
	}

	table, err := s.loadArtifactTable(path, relPath)
	if err != nil {
		s.respondWithError(w, http.StatusNotFound, "artifact file not found")
		return
	}

	rows := table.rows

	// Optional exact-value column filter (fcol = column index, fvals = comma-
	// separated allowed values, matched case-insensitively). Powers "Shells only".
	if fcolStr := q.Get("fcol"); fcolStr != "" {
		if fcol, err := strconv.Atoi(fcolStr); err == nil && fcol >= 0 {
			allowed := map[string]bool{}
			for _, v := range strings.Split(q.Get("fvals"), ",") {
				allowed[strings.ToLower(strings.TrimSpace(v))] = true
			}
			if len(allowed) > 0 {
				filtered := make([][]string, 0, len(rows))
				for _, row := range rows {
					if allowed[strings.ToLower(cellAt(row, fcol))] {
						filtered = append(filtered, row)
					}
				}
				rows = filtered
			}
		}
	}

	// Free-text filter: case-insensitive substring across all cells.
	if term := strings.ToLower(q.Get("q")); term != "" {
		filtered := make([][]string, 0, len(rows))
		for _, row := range rows {
			for _, cell := range row {
				if strings.Contains(strings.ToLower(cell), term) {
					filtered = append(filtered, row)
					break
				}
			}
		}
		rows = filtered
	}

	// Sort by a column index. A copy is sorted so the cached slice is never
	// reordered under a concurrent reader.
	if scStr := q.Get("sort"); scStr != "" {
		if sc, err := strconv.Atoi(scStr); err == nil && sc >= 0 && sc < len(table.headers) {
			asc := q.Get("dir") != "desc"
			sorted := make([][]string, len(rows))
			copy(sorted, rows)
			sort.SliceStable(sorted, func(i, j int) bool {
				a, b := cellAt(sorted[i], sc), cellAt(sorted[j], sc)
				an, aerr := strconv.ParseFloat(strings.TrimSpace(a), 64)
				bn, berr := strconv.ParseFloat(strings.TrimSpace(b), 64)
				if aerr == nil && berr == nil {
					if asc {
						return an < bn
					}
					return an > bn
				}
				al, bl := strings.ToLower(a), strings.ToLower(b)
				if asc {
					return al < bl
				}
				return al > bl
			})
			rows = sorted
		}
	}

	total := len(rows)

	page := 1
	if p, err := strconv.Atoi(q.Get("page")); err == nil && p > 0 {
		page = p
	}
	limit := 200
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
		if limit > 2000 {
			limit = 2000
		}
	}

	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	pageRows := rows[start:end]
	if pageRows == nil {
		pageRows = [][]string{}
	}

	response := map[string]any{
		"headers": table.headers,
		"rows":    pageRows,
		"total":   total,
		"page":    page,
		"limit":   limit,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// cellAt returns row[i], or "" when i is out of range (short rows are common in
// forensic CSVs and must not panic the sort/filter).
func cellAt(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return row[i]
}
