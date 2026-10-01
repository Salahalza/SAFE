package html_report

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Cross-artifact search bounds. The scan reads every artifact CSV once per query
// (no persistent index — a trigram FTS over ~760 MB of CSVs would add gigabytes
// to the case folder and break the lean, tool-agnostic evidence set of
// architectural principle #9). To stay responsive on a pathological multi-GB log
// the scan of a single file stops after searchRowScanCap rows and marks that
// group truncated (its Total then a lower bound), so coverage is never silently
// capped. maxHitsPerFile bounds only how many matching rows are RETURNED; the hit
// count is still exact unless the row cap is reached.
const (
	searchMaxHitsPerFile = 50
	searchRowScanCap     = 5_000_000
	searchMinQueryLen    = 2
	searchConcurrency    = 8
)

// searchGroup is one artifact's matches for a query.
type searchGroup struct {
	Artifact  string     `json:"artifact"`  // lab_report-relative path (slash-separated)
	Folder    string     `json:"folder"`    // Explorer group label (e.g. "Evtx", "Iis")
	Headers   []string   `json:"headers"`   // the CSV header row, for rendering matched rows
	Total     int        `json:"total"`     // matching rows found (exact unless Truncated)
	Truncated bool       `json:"truncated"` // row-scan cap hit; Total is a lower bound
	Rows      [][]string `json:"rows"`      // up to searchMaxHitsPerFile matching rows
}

// handleSearch scans every parsed artifact CSV for a case-insensitive substring
// and returns the matches grouped by artifact, most-hit first. It is the report's
// only cross-artifact search: the timeline, detections, and per-file table
// searches each cover one surface, so chasing an IOC (an IP, a hash, a filename)
// across the ~130 CSVs had no single entry point before this.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	resp := map[string]any{"query": q, "groups": []*searchGroup{}, "truncated": false, "scanned": 0}
	if len([]rune(q)) < searchMinQueryLen {
		writeJSON(w, resp)
		return
	}
	needle := strings.ToLower(q)

	// Candidate CSVs — same exclusions as the Explorer sidebar (the timeline and
	// behavior CSVs have their own dedicated search surfaces; timeline.db is the
	// derived cache). The folder label is derived here, in the single-threaded
	// walk: cases.Caser is NOT safe for concurrent use, so it must never be
	// touched from the scan goroutines below.
	type cand struct{ rel, abs, folder string }
	var cands []cand
	caser := cases.Title(language.English)
	_ = filepath.Walk(s.labReportDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".csv") {
			return nil
		}
		rel, rerr := filepath.Rel(s.labReportDir, path)
		if rerr != nil || rel == "timeline.csv" || rel == "behavior_hits.csv" || strings.HasSuffix(rel, "timeline.db") {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		cands = append(cands, cand{rel: relSlash, abs: path, folder: searchFolder(relSlash, caser)})
		return nil
	})

	groups := make([]*searchGroup, len(cands))
	var wg sync.WaitGroup
	sem := make(chan struct{}, searchConcurrency)
	var anyTrunc int32
	for i := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			g := searchOneFile(cands[i].abs, cands[i].rel, cands[i].folder, needle)
			if g != nil && g.Total > 0 {
				groups[i] = g
				if g.Truncated {
					atomic.StoreInt32(&anyTrunc, 1)
				}
			}
		}(i)
	}
	wg.Wait()

	out := make([]*searchGroup, 0, len(cands))
	for _, g := range groups {
		if g != nil {
			out = append(out, g)
		}
	}
	// Most-hit artifacts first, then by path for a stable order.
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Total != out[b].Total {
			return out[a].Total > out[b].Total
		}
		return out[a].Artifact < out[b].Artifact
	})

	resp["groups"] = out
	resp["truncated"] = anyTrunc == 1
	resp["scanned"] = len(cands)
	writeJSON(w, resp)
}

// searchOneFile streams one CSV and collects rows where any cell contains needle
// (already lowercased). It never caches the parse — searching would otherwise
// evict the Explorer's paging cache and pin hundreds of MB. Returns nil on an
// unreadable/empty file (best-effort: one bad artifact never fails the search).
func searchOneFile(absPath, rel, folder, needle string) *searchGroup {
	f, err := os.Open(absPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true

	header, err := reader.Read()
	if err != nil {
		return nil
	}
	g := &searchGroup{
		Artifact: rel,
		Folder:   folder,
		Headers:  append([]string(nil), header...), // ReuseRecord reuses the slice; copy it
	}

	scanned := 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		scanned++
		if scanned > searchRowScanCap {
			g.Truncated = true
			break
		}
		matched := false
		for _, cell := range row {
			if containsFold(cell, needle) {
				matched = true
				break
			}
		}
		if matched {
			g.Total++
			if len(g.Rows) < searchMaxHitsPerFile {
				g.Rows = append(g.Rows, append([]string(nil), row...))
			}
		}
	}
	return g
}

// containsFold reports whether s contains lowerNeedle, case-insensitively for
// ASCII. lowerNeedle must already be lowercase. It avoids allocating a lowercased
// copy of every cell (there are tens of millions across a large case), which a
// strings.Contains(strings.ToLower(cell), …) would. IOC terms — IPs, hashes,
// filenames, command fragments — are ASCII, so ASCII folding is sufficient.
func containsFold(s, lowerNeedle string) bool {
	n := len(lowerNeedle)
	if n == 0 {
		return true
	}
	if len(s) < n {
		return false
	}
	for i := 0; i+n <= len(s); i++ {
		j := 0
		for j < n && lowerASCII(s[i+j]) == lowerNeedle[j] {
			j++
		}
		if j == n {
			return true
		}
	}
	return false
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// searchFolder derives the Explorer group label for a slash-separated
// lab_report-relative CSV path, matching the Artifact Explorer sidebar grouping.
func searchFolder(rel string, caser cases.Caser) string {
	i := strings.LastIndex(rel, "/")
	if i < 0 {
		if strings.HasPrefix(rel, "mft_") {
			return "File System"
		}
		return "Root"
	}
	folder := strings.ReplaceAll(rel[:i], "_", " ")
	folder = caser.String(folder)
	if strings.EqualFold(folder, "mft") {
		return "File System"
	}
	return folder
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}
