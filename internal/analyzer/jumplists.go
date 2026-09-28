package analyzer

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/parsiya/golnk"
	"github.com/richardlehane/mscfb"
)

// JumpListsParser parses Windows Jump Lists (.automaticDestinations-ms and .customDestinations-ms)
// to reconstruct the recently and frequently accessed files and folders of users.
type JumpListsParser struct{}

func (p *JumpListsParser) Name() string { return "jumplists" }

type jumplistEntry struct {
	SID            string
	Type           string // "automatic" or "custom"
	AppID          string // derived from the filename (e.g. f01b4d95cf55d32a)
	EntryID        string
	Path           string
	Arguments      string
	AccessCount    string
	Pinned         string
	LastAccessUTC  string
	LnkCreatedUTC  string
	LnkModifiedUTC string
	LnkAccessedUTC string
}

func (p *JumpListsParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error

	jumpListsGlob := filepath.Join(caseDir, "modules", "*_jump_lists")
	matches, err := filepath.Glob(jumpListsGlob)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("glob jump lists: %w", err)}
	}
	if len(matches) == 0 {
		return nil, stats, nil
	}
	jumpListsRoot := matches[0]

	userDirs, err := os.ReadDir(jumpListsRoot)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("read jump lists root: %w", err)}
	}

	outDir := filepath.Join(labReportDir, "jump_lists")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, []error{fmt.Errorf("create output dir: %w", err)}
	}

	var entries []jumplistEntry
	usersProcessed := 0
	usersWithData := 0
	totalAutoEntries := 0
	totalCustomEntries := 0

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

		// 1. Process AutomaticDestinations
		autoDir := filepath.Join(jumpListsRoot, sid, "Recent", "AutomaticDestinations")
		if info, err := os.Stat(autoDir); err == nil && info.IsDir() {
			files, ferr := os.ReadDir(autoDir)
			if ferr == nil {
				for _, f := range files {
					if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".automaticdestinations-ms") {
						continue
					}
					appID := strings.TrimSuffix(strings.ToLower(f.Name()), ".automaticdestinations-ms")
					filePath := filepath.Join(autoDir, f.Name())
					
					parsed, err := parseAutomaticDestinations(filePath, sid, appID)
					if err != nil {
						errs = append(errs, fmt.Errorf("parse automatic destinations %s/%s: %w", sid, f.Name(), err))
						continue
					}
					if len(parsed) > 0 {
						entries = append(entries, parsed...)
						totalAutoEntries += len(parsed)
						userHasData = true
					}
				}
			}
		}

		// 2. Process CustomDestinations
		customDir := filepath.Join(jumpListsRoot, sid, "Recent", "CustomDestinations")
		if info, err := os.Stat(customDir); err == nil && info.IsDir() {
			files, ferr := os.ReadDir(customDir)
			if ferr == nil {
				for _, f := range files {
					if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".customdestinations-ms") {
						continue
					}
					appID := strings.TrimSuffix(strings.ToLower(f.Name()), ".customdestinations-ms")
					filePath := filepath.Join(customDir, f.Name())
					
					parsed, err := parseCustomDestinations(filePath, sid, appID)
					if err != nil {
						errs = append(errs, fmt.Errorf("parse custom destinations %s/%s: %w", sid, f.Name(), err))
						continue
					}
					if len(parsed) > 0 {
						entries = append(entries, parsed...)
						totalCustomEntries += len(parsed)
						userHasData = true
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
	stats["total_automatic_entries"] = totalAutoEntries
	stats["total_custom_entries"] = totalCustomEntries
	stats["total_entries"] = len(entries)

	if len(entries) == 0 {
		return nil, stats, errs
	}

	csvPath := filepath.Join(outDir, "jump_lists.csv")
	if err := writeJumpListsCSV(csvPath, entries); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write jump_lists.csv: %w", err))
	}

	return []string{csvPath}, stats, errs
}

func parseAutomaticDestinations(path string, sid string, appID string) ([]jumplistEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	doc, err := mscfb.New(f)
	if err != nil {
		return nil, fmt.Errorf("init mscfb: %w", err)
	}

	streams := make(map[string][]byte)
	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		data, readErr := io.ReadAll(entry)
		if readErr != nil {
			continue
		}
		streams[strings.ToLower(entry.Name)] = data
	}

	destListData, ok := streams["destlist"]
	if !ok {
		return nil, nil // No DestList stream, skip
	}

	if len(destListData) < 32 {
		return nil, fmt.Errorf("DestList stream too short (%d bytes)", len(destListData))
	}

	version := binary.LittleEndian.Uint32(destListData[0:4])
	totalEntries := binary.LittleEndian.Uint32(destListData[4:8])

	var pathSizeOffset int
	var pathStringOffset int
	var fixedEntryHeaderSize int
	var hasAccessCount bool

	if version == 1 {
		pathSizeOffset = 112
		pathStringOffset = 114
		fixedEntryHeaderSize = 114
		hasAccessCount = false
	} else if version == 2 {
		// v2 uses the same field layout as v1 but adds an access count.
		// Documented in libfwsi and forensic community references.
		pathSizeOffset = 112
		pathStringOffset = 114
		fixedEntryHeaderSize = 114
		hasAccessCount = true
	} else if version >= 3 {
		pathSizeOffset = 128
		pathStringOffset = 130
		fixedEntryHeaderSize = 130
		hasAccessCount = true
	} else {
		return nil, fmt.Errorf("unsupported DestList version: %d", version)
	}

	var results []jumplistEntry
	offset := 32

	for i := 0; i < int(totalEntries); i++ {
		if offset+fixedEntryHeaderSize > len(destListData) {
			break
		}

		entryID := binary.LittleEndian.Uint32(destListData[offset+88 : offset+92])
		lastAccessFT := binary.LittleEndian.Uint64(destListData[offset+100 : offset+108])
		pinStatus := binary.LittleEndian.Uint32(destListData[offset+108 : offset+112])
		
		var accessCountStr string
		if hasAccessCount {
			accessCount := binary.LittleEndian.Uint32(destListData[offset+112 : offset+116])
			accessCountStr = fmt.Sprintf("%d", accessCount)
		}

		pathSize := binary.LittleEndian.Uint16(destListData[offset+pathSizeOffset : offset+pathSizeOffset+2])
		
		stringOffset := offset + pathStringOffset
		if stringOffset+int(pathSize)*2 > len(destListData) {
			break
		}

		pathRunes := make([]rune, pathSize)
		for r := 0; r < int(pathSize); r++ {
			pathRunes[r] = rune(binary.LittleEndian.Uint16(destListData[stringOffset+r*2 : stringOffset+r*2+2]))
		}
		pathStr := string(pathRunes)

		var lastAccessStr string
		if lastAccessFT > 0 {
			lastAccessTime := filetimeToTime(lastAccessFT)
			lastAccessStr = lastAccessTime.Format(time.RFC3339)
		}

		pinnedStr := "0"
		if pinStatus != 0xFFFFFFFF {
			pinnedStr = "1"
		}

		// Look up corresponding LNK stream
		streamKey := fmt.Sprintf("%x", entryID)
		lnkCreatedStr := ""
		lnkModifiedStr := ""
		lnkAccessedStr := ""
		lnkArgs := ""

		if lnkData, ok := streams[streamKey]; ok {
			lnkObj, lerr := lnk.Read(bytes.NewReader(lnkData), uint64(len(lnkData)))
			if lerr == nil {
				if !lnkObj.Header.CreationTime.IsZero() {
					lnkCreatedStr = lnkObj.Header.CreationTime.UTC().Format(time.RFC3339)
				}
				if !lnkObj.Header.WriteTime.IsZero() {
					lnkModifiedStr = lnkObj.Header.WriteTime.UTC().Format(time.RFC3339)
				}
				if !lnkObj.Header.AccessTime.IsZero() {
					lnkAccessedStr = lnkObj.Header.AccessTime.UTC().Format(time.RFC3339)
				}
				lnkArgs = lnkObj.StringData.CommandLineArguments
				
				// If path is empty, fall back to LNK path
				if pathStr == "" {
					pathStr = lnkObj.LinkInfo.LocalBasePath
					if pathStr == "" {
						pathStr = lnkObj.StringData.RelativePath
					}
				}
			}
		}

		results = append(results, jumplistEntry{
			SID:            sid,
			Type:           "automatic",
			AppID:          appID,
			EntryID:        fmt.Sprintf("%d", entryID),
			Path:           pathStr,
			Arguments:      lnkArgs,
			AccessCount:    accessCountStr,
			Pinned:         pinnedStr,
			LastAccessUTC:  lastAccessStr,
			LnkCreatedUTC:  lnkCreatedStr,
			LnkModifiedUTC: lnkModifiedStr,
			LnkAccessedUTC: lnkAccessedStr,
		})

		// Advance to next entry: fixed header + variable path (UTF-16LE chars * 2) + 4 bytes padding.
		// Guard against the stride exceeding the available data to prevent silent
		// truncation of remaining entries on malformed or truncated files.
		var stride int
		if version == 1 || version == 2 {
			stride = 114 + int(pathSize)*2 + 4
		} else {
			stride = 130 + int(pathSize)*2 + 4
		}
		if offset+stride > len(destListData) {
			break
		}
		offset += stride
	}

	return results, nil
}

func parseCustomDestinations(path string, sid string, appID string) ([]jumplistEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	sig := []byte{
		0x4c, 0x00, 0x00, 0x00,
		0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	}

	var results []jumplistEntry
	idx := 0
	entryIndex := 0

	for {
		pos := bytes.Index(data[idx:], sig)
		if pos == -1 {
			break
		}
		absPos := idx + pos
		lnkData := data[absPos:]
		
		lnkObj, lerr := lnk.Read(bytes.NewReader(lnkData), uint64(len(lnkData)))
		if lerr == nil {
			pathStr := lnkObj.LinkInfo.LocalBasePath
			if pathStr == "" {
				pathStr = lnkObj.StringData.RelativePath
			}

			lnkCreatedStr := ""
			lnkModifiedStr := ""
			lnkAccessedStr := ""

			if !lnkObj.Header.CreationTime.IsZero() {
				lnkCreatedStr = lnkObj.Header.CreationTime.UTC().Format(time.RFC3339)
			}
			if !lnkObj.Header.WriteTime.IsZero() {
				lnkModifiedStr = lnkObj.Header.WriteTime.UTC().Format(time.RFC3339)
			}
			if !lnkObj.Header.AccessTime.IsZero() {
				lnkAccessedStr = lnkObj.Header.AccessTime.UTC().Format(time.RFC3339)
			}

			results = append(results, jumplistEntry{
				SID:            sid,
				Type:           "custom",
				AppID:          appID,
				EntryID:        fmt.Sprintf("%d", entryIndex),
				Path:           pathStr,
				Arguments:      lnkObj.StringData.CommandLineArguments,
				AccessCount:    "",
				Pinned:         "0", // custom categories usually don't carry pinning metadata in the entry
				LastAccessUTC:  "",
				LnkCreatedUTC:  lnkCreatedStr,
				LnkModifiedUTC: lnkModifiedStr,
				LnkAccessedUTC: lnkAccessedStr,
			})
			entryIndex++
		}

		idx = absPos + len(sig)
	}

	return results, nil
}

func writeJumpListsCSV(path string, entries []jumplistEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"sid", "type", "app_id", "entry_id", "path", "arguments",
		"access_count", "pinned", "last_accessed_utc", "lnk_created_utc", "lnk_modified_utc", "lnk_accessed_utc",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, e := range entries {
		if err := w.Write([]string{
			e.SID,
			e.Type,
			e.AppID,
			e.EntryID,
			csvSafe(e.Path),
			csvSafe(e.Arguments),
			e.AccessCount,
			e.Pinned,
			e.LastAccessUTC,
			e.LnkCreatedUTC,
			e.LnkModifiedUTC,
			e.LnkAccessedUTC,
		}); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
