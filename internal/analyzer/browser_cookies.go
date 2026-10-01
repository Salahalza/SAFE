package analyzer

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// BrowserCookiesParser parses browser cookies databases (Chrome/Edge Cookies, Firefox cookies.sqlite)
// for each user profile.
type BrowserCookiesParser struct{}

func (p *BrowserCookiesParser) Name() string { return "browser_cookies" }

type browserCookieEntry struct {
	SID         string
	Browser     string
	Profile     string
	Domain      string
	Name        string
	Path        string
	Value       string
	// HasEncryptedValue marks a cookie whose real value lives in the encrypted
	// (DPAPI/AES-GCM) column rather than the legacy plaintext one. On modern
	// Chrome/Edge that is essentially every cookie, so without this flag a blank
	// Value reads as "no value" when the truth is "encrypted, not yet decoded".
	HasEncryptedValue bool
	IsSecure          int
	IsHttpOnly        int
	CreatedUTC        string
	ExpiresUTC        string
}

func (p *BrowserCookiesParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
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

	var entries []browserCookieEntry
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
					
					// Chromium cookies can be at profile root or in Network/
					cookieFiles := []string{
						filepath.Join(chromePath, profileName, "Cookies"),
						filepath.Join(chromePath, profileName, "Network", "Cookies"),
					}
					// Chromium cookies are at profile root or Network/ — take whichever
					// exists first to avoid double-counting migration artifacts.
					for _, cf := range cookieFiles {
						if _, err := os.Stat(cf); err == nil {
							parsed, err := parseChromiumCookies(cf, sid, "chrome", profileName)
							if err != nil {
								errs = append(errs, fmt.Errorf("parse Chrome cookies %s/%s: %w", sid, profileName, err))
							} else if len(parsed) > 0 {
								entries = append(entries, parsed...)
								chromeEntries += len(parsed)
								userHasData = true
							}
							break // only parse one cookie file per profile
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
					
					cookieFiles := []string{
						filepath.Join(edgePath, profileName, "Cookies"),
						filepath.Join(edgePath, profileName, "Network", "Cookies"),
					}
					// Chromium cookies are at profile root or Network/ — take whichever
					// exists first to avoid double-counting migration artifacts.
					for _, cf := range cookieFiles {
						if _, err := os.Stat(cf); err == nil {
							parsed, err := parseChromiumCookies(cf, sid, "edge", profileName)
							if err != nil {
								errs = append(errs, fmt.Errorf("parse Edge cookies %s/%s: %w", sid, profileName, err))
							} else if len(parsed) > 0 {
								entries = append(entries, parsed...)
								edgeEntries += len(parsed)
								userHasData = true
							}
							break // only parse one cookie file per profile
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
					cookiesFile := filepath.Join(firefoxPath, profileName, "cookies.sqlite")
					if _, err := os.Stat(cookiesFile); err == nil {
						parsed, err := parseFirefoxCookies(cookiesFile, sid, profileName)
						if err != nil {
							errs = append(errs, fmt.Errorf("parse Firefox cookies %s/%s: %w", sid, profileName, err))
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

	csvPath := filepath.Join(outDir, "cookies.csv")
	if err := writeCookiesCSV(csvPath, entries); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write cookies.csv: %w", err))
	}

	return []string{csvPath}, stats, errs
}

func parseChromiumCookies(dbPath string, sid string, browser string, profile string) ([]browserCookieEntry, error) {
	db, err := openCollectedSQLite(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	defer db.Close()

	// encrypted_value carries the real cookie value on modern Chromium (the
	// plaintext `value` column is left empty). SAFE does not decrypt it here — that
	// needs the profile's DPAPI-protected Local State key and is a separate feature
	// — but reading its presence lets the output flag which cookies have a value
	// that is encrypted rather than genuinely absent.
	rows, err := db.Query("SELECT host_key, name, path, value, is_secure, is_httponly, creation_utc, expires_utc, encrypted_value FROM cookies")
	if err != nil {
		return nil, fmt.Errorf("query cookies table: %w", err)
	}
	defer rows.Close()

	var results []browserCookieEntry
	for rows.Next() {
		var hostKey, name, path, value string
		var isSecure, isHttpOnly int
		var creationUtc, expiresUtc int64
		var encryptedValue []byte
		if err := rows.Scan(&hostKey, &name, &path, &value, &isSecure, &isHttpOnly, &creationUtc, &expiresUtc, &encryptedValue); err != nil {
			continue
		}

		var createdStr, expiresStr string
		if creationUtc > 0 {
			const epochOffset = 11644473600000000
			unixSecs := (creationUtc - epochOffset) / 1000000
			unixNanos := ((creationUtc - epochOffset) % 1000000) * 1000
			createdStr = time.Unix(unixSecs, unixNanos).UTC().Format(time.RFC3339)
		}
		if expiresUtc > 0 {
			const epochOffset = 11644473600000000
			unixSecs := (expiresUtc - epochOffset) / 1000000
			unixNanos := ((expiresUtc - epochOffset) % 1000000) * 1000
			expiresStr = time.Unix(unixSecs, unixNanos).UTC().Format(time.RFC3339)
		}

		results = append(results, browserCookieEntry{
			SID:               sid,
			Browser:           browser,
			Profile:           profile,
			Domain:            hostKey,
			Name:              name,
			Path:              path,
			Value:             value,
			HasEncryptedValue: len(encryptedValue) > 0,
			IsSecure:          isSecure,
			IsHttpOnly:        isHttpOnly,
			CreatedUTC:        createdStr,
			ExpiresUTC:        expiresStr,
		})
	}

	return results, nil
}

func parseFirefoxCookies(dbPath string, sid string, profile string) ([]browserCookieEntry, error) {
	db, err := openCollectedSQLite(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT host, name, path, value, isSecure, isHttpOnly, creationTime, expiry FROM moz_cookies")
	if err != nil {
		return nil, fmt.Errorf("query moz_cookies table: %w", err)
	}
	defer rows.Close()

	var results []browserCookieEntry
	for rows.Next() {
		var host, name, path, value string
		var isSecure, isHttpOnly int
		var creationTime, expiry int64
		if err := rows.Scan(&host, &name, &path, &value, &isSecure, &isHttpOnly, &creationTime, &expiry); err != nil {
			continue
		}

		var createdStr, expiresStr string
		if creationTime > 0 {
			createdStr = time.Unix(creationTime/1000000, (creationTime%1000000)*1000).UTC().Format(time.RFC3339)
		}
		if expiry > 0 {
			expiresStr = time.Unix(expiry, 0).UTC().Format(time.RFC3339)
		}

		results = append(results, browserCookieEntry{
			SID:        sid,
			Browser:    "firefox",
			Profile:    profile,
			Domain:     host,
			Name:       name,
			Path:       path,
			Value:      value,
			IsSecure:   isSecure,
			IsHttpOnly: isHttpOnly,
			CreatedUTC: createdStr,
			ExpiresUTC: expiresStr,
		})
	}

	return results, nil
}

func writeCookiesCSV(path string, entries []browserCookieEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"sid", "browser", "profile", "domain", "name", "path", "value", "has_encrypted_value", "is_secure", "is_httponly", "created_utc", "expires_utc",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, e := range entries {
		if err := w.Write([]string{
			e.SID,
			e.Browser,
			e.Profile,
			csvSafe(e.Domain),
			csvSafe(e.Name),
			csvSafe(e.Path),
			csvSafe(e.Value),
			fmt.Sprintf("%t", e.HasEncryptedValue),
			fmt.Sprintf("%d", e.IsSecure),
			fmt.Sprintf("%d", e.IsHttpOnly),
			e.CreatedUTC,
			e.ExpiresUTC,
		}); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
