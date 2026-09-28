package analyzer

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// BrowserHistoryParser parses browser history databases (Chrome/Edge History, Firefox places.sqlite)
// for each user profile.
type BrowserHistoryParser struct{}

func (p *BrowserHistoryParser) Name() string { return "browser_history" }

type browserHistoryEntry struct {
	SID          string
	Browser      string
	Profile      string
	URL          string
	Title        string
	VisitCount   int
	TypedCount   int
	LastVisitUTC string
}

func (p *BrowserHistoryParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error

	browserGlob := filepath.Join(caseDir, "modules", "*_browser_artifacts")
	matches, err := filepath.Glob(browserGlob)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("glob browser artifacts: %w", err)}
	}
	if len(matches) == 0 {
		return nil, stats, nil
	}
	browserRoot := matches[0]

	userDirs, err := os.ReadDir(browserRoot)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("read browser artifacts root: %w", err)}
	}

	outDir := filepath.Join(labReportDir, "browser")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, []error{fmt.Errorf("create output dir: %w", err)}
	}

	var entries []browserHistoryEntry
	usersProcessed := 0
	usersWithData := 0
	chromeEntries := 0
	edgeEntries := 0
	firefoxEntries := 0

	for uIdx, ud := range userDirs {
		if report != nil {
			report(uIdx, len(userDirs))
		}
		if !ud.IsDir() {
			continue
		}
		sid := ud.Name()
		usersProcessed++
		userHasData := false

		// 1. Process Chrome
		chromePath := filepath.Join(browserRoot, sid, "Chrome")
		if info, err := os.Stat(chromePath); err == nil && info.IsDir() {
			profiles, perr := os.ReadDir(chromePath)
			if perr == nil {
				for _, pr := range profiles {
					if !pr.IsDir() {
						continue
					}
					profileName := pr.Name()
					historyFile := filepath.Join(chromePath, profileName, "History")
					if _, err := os.Stat(historyFile); err == nil {
						parsed, err := parseChromiumHistory(historyFile, sid, "chrome", profileName)
						if err != nil {
							errs = append(errs, fmt.Errorf("parse Chrome history %s/%s: %w", sid, profileName, err))
							continue
						}
						if len(parsed) > 0 {
							entries = append(entries, parsed...)
							chromeEntries += len(parsed)
							userHasData = true
						}
					}
				}
			}
		}

		// 2. Process Edge
		edgePath := filepath.Join(browserRoot, sid, "Edge")
		if info, err := os.Stat(edgePath); err == nil && info.IsDir() {
			profiles, perr := os.ReadDir(edgePath)
			if perr == nil {
				for _, pr := range profiles {
					if !pr.IsDir() {
						continue
					}
					profileName := pr.Name()
					historyFile := filepath.Join(edgePath, profileName, "History")
					if _, err := os.Stat(historyFile); err == nil {
						parsed, err := parseChromiumHistory(historyFile, sid, "edge", profileName)
						if err != nil {
							errs = append(errs, fmt.Errorf("parse Edge history %s/%s: %w", sid, profileName, err))
							continue
						}
						if len(parsed) > 0 {
							entries = append(entries, parsed...)
							edgeEntries += len(parsed)
							userHasData = true
						}
					}
				}
			}
		}

		// 3. Process Firefox
		firefoxPath := filepath.Join(browserRoot, sid, "Firefox", "Profiles")
		if info, err := os.Stat(firefoxPath); err == nil && info.IsDir() {
			profiles, perr := os.ReadDir(firefoxPath)
			if perr == nil {
				for _, pr := range profiles {
					if !pr.IsDir() {
						continue
					}
					profileName := pr.Name()
					placesFile := filepath.Join(firefoxPath, profileName, "places.sqlite")
					if _, err := os.Stat(placesFile); err == nil {
						parsed, err := parseFirefoxHistory(placesFile, sid, profileName)
						if err != nil {
							errs = append(errs, fmt.Errorf("parse Firefox history %s/%s: %w", sid, profileName, err))
							continue
						}
						if len(parsed) > 0 {
							entries = append(entries, parsed...)
							firefoxEntries += len(parsed)
							userHasData = true
						}
					}
				}
			}
		}

		if userHasData {
			usersWithData++
		}
	}

	if report != nil {
		report(len(userDirs), len(userDirs))
	}

	stats["users_processed"] = usersProcessed
	stats["users_with_data"] = usersWithData
	stats["chrome_entries"] = chromeEntries
	stats["edge_entries"] = edgeEntries
	stats["firefox_entries"] = firefoxEntries
	stats["total_entries"] = len(entries)

	if len(entries) == 0 {
		return nil, stats, errs
	}

	csvPath := filepath.Join(outDir, "history.csv")
	if err := writeHistoryCSV(csvPath, entries); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write history.csv: %w", err))
	}

	return []string{csvPath}, stats, errs
}

func parseChromiumHistory(dbPath string, sid string, browser string, profile string) ([]browserHistoryEntry, error) {
	db, err := openCollectedSQLite(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	defer db.Close()

	// Query URLs
	rows, err := db.Query("SELECT url, title, visit_count, typed_count, last_visit_time FROM urls")
	if err != nil {
		// Table might not exist or be empty/corrupt
		return nil, fmt.Errorf("query urls table: %w", err)
	}
	defer rows.Close()

	var results []browserHistoryEntry
	for rows.Next() {
		var url, title string
		var visitCount, typedCount int
		var lastVisitTime int64
		if err := rows.Scan(&url, &title, &visitCount, &typedCount, &lastVisitTime); err != nil {
			continue // skip malformed row
		}

		var lastVisitStr string
		if lastVisitTime > 0 {
			const epochOffset = 11644473600000000
			unixSecs := (lastVisitTime - epochOffset) / 1000000
			unixNanos := ((lastVisitTime - epochOffset) % 1000000) * 1000
			lastVisitStr = time.Unix(unixSecs, unixNanos).UTC().Format(time.RFC3339)
		}

		results = append(results, browserHistoryEntry{
			SID:          sid,
			Browser:      browser,
			Profile:      profile,
			URL:          url,
			Title:        title,
			VisitCount:   visitCount,
			TypedCount:   typedCount,
			LastVisitUTC: lastVisitStr,
		})
	}

	return results, nil
}

func parseFirefoxHistory(dbPath string, sid string, profile string) ([]browserHistoryEntry, error) {
	db, err := openCollectedSQLite(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT url, title, visit_count, typed, last_visit_date FROM moz_places WHERE visit_count > 0 OR last_visit_date IS NOT NULL")
	if err != nil {
		return nil, fmt.Errorf("query moz_places table: %w", err)
	}
	defer rows.Close()

	var results []browserHistoryEntry
	for rows.Next() {
		var url string
		var title interface{} // title can be NULL in sqlite, map to interface or string pointer
		var visitCount, typed int
		var lastVisitDate interface{} // last_visit_date can be NULL
		if err := rows.Scan(&url, &title, &visitCount, &typed, &lastVisitDate); err != nil {
			continue
		}

		titleStr := ""
		if t, ok := title.(string); ok {
			titleStr = t
		}

		var lastVisitStr string
		if lastVisitDate != nil {
			if lvd, ok := lastVisitDate.(int64); ok && lvd > 0 {
				lastVisitStr = time.Unix(lvd/1000000, (lvd%1000000)*1000).UTC().Format(time.RFC3339)
			}
		}

		results = append(results, browserHistoryEntry{
			SID:          sid,
			Browser:      "firefox",
			Profile:      profile,
			URL:          url,
			Title:        titleStr,
			VisitCount:   visitCount,
			TypedCount:   typed,
			LastVisitUTC: lastVisitStr,
		})
	}

	return results, nil
}

func writeHistoryCSV(path string, entries []browserHistoryEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"sid", "browser", "profile", "url", "title", "visit_count", "typed_count", "last_visit_utc",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, e := range entries {
		if err := w.Write([]string{
			e.SID,
			e.Browser,
			e.Profile,
			csvSafe(e.URL),
			csvSafe(e.Title),
			fmt.Sprintf("%d", e.VisitCount),
			fmt.Sprintf("%d", e.TypedCount),
			e.LastVisitUTC,
		}); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
