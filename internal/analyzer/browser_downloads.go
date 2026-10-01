package analyzer

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// BrowserDownloadsParser parses browser downloads history (Chrome/Edge downloads table, Firefox places/downloads.sqlite)
// for each user profile.
type BrowserDownloadsParser struct{}

func (p *BrowserDownloadsParser) Name() string { return "browser_downloads" }

type browserDownloadEntry struct {
	SID          string
	Browser      string
	Profile      string
	URL          string
	TargetPath   string
	TotalBytes   int64
	State        string
	StartTimeUTC string
}

func (p *BrowserDownloadsParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
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

	var entries []browserDownloadEntry
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
						parsed, err := parseChromiumDownloads(historyFile, sid, "chrome", profileName)
						if err != nil {
							errs = append(errs, fmt.Errorf("parse Chrome downloads %s/%s: %w", sid, profileName, err))
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
						parsed, err := parseChromiumDownloads(historyFile, sid, "edge", profileName)
						if err != nil {
							errs = append(errs, fmt.Errorf("parse Edge downloads %s/%s: %w", sid, profileName, err))
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
						parsed, err := parseFirefoxPlacesDownloads(placesFile, sid, profileName)
						if err != nil {
							errs = append(errs, fmt.Errorf("parse Firefox places downloads %s/%s: %w", sid, profileName, err))
							continue
						}
						if len(parsed) > 0 {
							entries = append(entries, parsed...)
							firefoxEntries += len(parsed)
							userHasData = true
						}
					}

					downloadsFile := filepath.Join(firefoxPath, profileName, "downloads.sqlite")
					if _, err := os.Stat(downloadsFile); err == nil {
						parsed, err := parseFirefoxDownloadsLegacy(downloadsFile, sid, profileName)
						if err != nil {
							errs = append(errs, fmt.Errorf("parse Firefox legacy downloads %s/%s: %w", sid, profileName, err))
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

	csvPath := filepath.Join(outDir, "downloads.csv")
	if err := writeDownloadsCSV(csvPath, entries); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write downloads.csv: %w", err))
	}

	return []string{csvPath}, stats, errs
}

func parseChromiumDownloads(dbPath string, sid string, browser string, profile string) ([]browserDownloadEntry, error) {
	db, err := openCollectedSQLite(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	defer db.Close()

	// Use a correlated MIN to pick the lowest chain_index (the original source
	// URL) for each download. The previous WHERE chain_index = 0 silently dropped
	// downloads whose url_chain starts at a higher index (e.g. redirected files).
	query := `
		SELECT d.target_path, d.start_time, d.total_bytes, d.state, c.url
		FROM downloads d
		LEFT JOIN downloads_url_chains c ON d.id = c.id
		  AND c.chain_index = (
		    SELECT MIN(chain_index) FROM downloads_url_chains WHERE id = d.id
		  )
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query downloads: %w", err)
	}
	defer rows.Close()

	var results []browserDownloadEntry
	for rows.Next() {
		var targetPath, url string
		var startTime, totalBytes int64
		var state int
		if err := rows.Scan(&targetPath, &startTime, &totalBytes, &state, &url); err != nil {
			continue
		}

		var startStr string
		if startTime > 0 {
			const epochOffset = 11644473600000000
			unixSecs := (startTime - epochOffset) / 1000000
			unixNanos := ((startTime - epochOffset) % 1000000) * 1000
			startStr = time.Unix(unixSecs, unixNanos).UTC().Format(time.RFC3339)
		}

		stateStr := "unknown"
		switch state {
		case 0:
			stateStr = "in_progress"
		case 1:
			stateStr = "complete"
		case 2:
			stateStr = "cancelled"
		case 3:
			stateStr = "failed"
		}

		results = append(results, browserDownloadEntry{
			SID:          sid,
			Browser:      browser,
			Profile:      profile,
			URL:          url,
			TargetPath:   targetPath,
			TotalBytes:   totalBytes,
			State:        stateStr,
			StartTimeUTC: startStr,
		})
	}

	return results, nil
}

func parseFirefoxPlacesDownloads(dbPath string, sid string, profile string) ([]browserDownloadEntry, error) {
	db, err := openCollectedSQLite(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	defer db.Close()

	query := `
		SELECT p.url, a.content, a.dateAdded 
		FROM moz_places p 
		JOIN moz_annos a ON p.id = a.place_id 
		JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id 
		WHERE attr.name = 'downloads/destinationFileURI'
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query places downloads: %w", err)
	}
	defer rows.Close()

	var results []browserDownloadEntry
	for rows.Next() {
		var url, content string
		var dateAdded int64
		if err := rows.Scan(&url, &content, &dateAdded); err != nil {
			continue
		}

		// Firefox content stores URI like file:///C:/Users/...
		// Normalize to target path if it starts with file:///
		targetPath := content
		if strings.HasPrefix(strings.ToLower(content), "file:///") {
			targetPath = strings.TrimPrefix(content, "file:///")
			// On Windows, targetPath will now be like C:/Users/...
			targetPath = filepath.FromSlash(targetPath)
		}

		var startStr string
		if dateAdded > 0 {
			startStr = time.Unix(dateAdded/1000000, (dateAdded%1000000)*1000).UTC().Format(time.RFC3339)
		}

		results = append(results, browserDownloadEntry{
			SID:          sid,
			Browser:      "firefox",
			Profile:      profile,
			URL:          url,
			TargetPath:   targetPath,
			TotalBytes:   0, // Not directly stored in target path annotation
			State:        "complete",
			StartTimeUTC: startStr,
		})
	}

	return results, nil
}

func parseFirefoxDownloadsLegacy(dbPath string, sid string, profile string) ([]browserDownloadEntry, error) {
	db, err := openCollectedSQLite(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	defer db.Close()

	query := `
		SELECT source, target, startTime, state, totalBytes 
		FROM moz_downloads
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query legacy downloads: %w", err)
	}
	defer rows.Close()

	var results []browserDownloadEntry
	for rows.Next() {
		var source, target string
		var startTime, totalBytes int64
		var state int
		if err := rows.Scan(&source, &target, &startTime, &state, &totalBytes); err != nil {
			continue
		}

		targetPath := target
		if strings.HasPrefix(strings.ToLower(target), "file:///") {
			targetPath = strings.TrimPrefix(target, "file:///")
			targetPath = filepath.FromSlash(targetPath)
		}

		var startStr string
		if startTime > 0 {
			// startTime in downloads.sqlite is usually in microseconds
			startStr = time.Unix(startTime/1000000, (startTime%1000000)*1000).UTC().Format(time.RFC3339)
		}

		stateStr := "unknown"
		switch state {
		case 0:
			stateStr = "in_progress"
		case 1:
			stateStr = "complete"
		case 2:
			stateStr = "cancelled"
		case 3:
			stateStr = "failed"
		}

		results = append(results, browserDownloadEntry{
			SID:          sid,
			Browser:      "firefox",
			Profile:      profile,
			URL:          source,
			TargetPath:   targetPath,
			TotalBytes:   totalBytes,
			State:        stateStr,
			StartTimeUTC: startStr,
		})
	}

	return results, nil
}

func writeDownloadsCSV(path string, entries []browserDownloadEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"sid", "browser", "profile", "url", "target_path", "total_bytes", "state", "start_time_utc",
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
			csvSafe(e.TargetPath),
			fmt.Sprintf("%d", e.TotalBytes),
			e.State,
			e.StartTimeUTC,
		}); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
