package analyzer

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"www.velocidex.com/golang/regparser"
)

// ShellBagsParser parses BagMRU keys from NTUSER.DAT and UsrClass.dat registry hives
// to reconstruct the folder browsing history of users.
type ShellBagsParser struct{}

func (p *ShellBagsParser) Name() string { return "shellbags" }

type shellbagEntry struct {
	SID          string
	SourceHive   string
	MRUPath      string
	FolderPath   string
	LastWriteUTC string
	SubkeyIndex  string
}

func (p *ShellBagsParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error

	hivesGlob := filepath.Join(caseDir, "modules", "*_user_hives_collection")
	matches, err := filepath.Glob(hivesGlob)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("glob user hives: %w", err)}
	}
	if len(matches) == 0 {
		return nil, stats, nil
	}
	hivesRoot := matches[0]

	userDirs, err := os.ReadDir(hivesRoot)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("read user hives root: %w", err)}
	}

	outDir := filepath.Join(labReportDir, "shellbags")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, []error{fmt.Errorf("create output dir: %w", err)}
	}

	// First pass: locate and open all BagMRU keys to count total nodes for progress
	type targetHive struct {
		sid      string
		hiveName string
		keyNode  *regparser.CM_KEY_NODE
		file     *os.File
	}
	var targets []targetHive
	totalKeys := 0

	for _, ud := range userDirs {
		if !ud.IsDir() {
			continue
		}
		sid := ud.Name()

		// 1. Check NTUSER.DAT
		ntuserPath := filepath.Join(hivesRoot, sid, "NTUSER.DAT")
		if _, err := os.Stat(ntuserPath); err == nil {
			if f, oerr := os.Open(ntuserPath); oerr == nil {
				if reg, rerr := regparser.NewRegistry(f); rerr == nil {
					key := reg.OpenKey(`Software\Microsoft\Windows\Shell\BagMRU`)
					if key != nil {
						totalKeys += countSubkeys(key) + 1
						targets = append(targets, targetHive{
							sid:      sid,
							hiveName: "NTUSER.DAT",
							keyNode:  key,
							file:     f,
						})
					} else {
						f.Close()
					}
				} else {
					f.Close()
				}
			}
		}

		// 2. Check UsrClass.dat
		usrclassPath := filepath.Join(hivesRoot, sid, "UsrClass.dat")
		if _, err := os.Stat(usrclassPath); err == nil {
			if f, oerr := os.Open(usrclassPath); oerr == nil {
				if reg, rerr := regparser.NewRegistry(f); rerr == nil {
					key := reg.OpenKey(`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`)
					if key != nil {
						totalKeys += countSubkeys(key) + 1
						targets = append(targets, targetHive{
							sid:      sid,
							hiveName: "UsrClass.dat",
							keyNode:  key,
							file:     f,
						})
					} else {
						f.Close()
					}
				} else {
					f.Close()
				}
			}
		}
	}

	doneKeys := 0
	advance := func() {
		doneKeys++
		if report != nil {
			report(doneKeys, totalKeys)
		}
	}

	var entries []shellbagEntry
	hivesWithData := 0
	usersProcessed := make(map[string]bool)

	// Second pass: recursively parse the BagMRU hierarchy; close files as we go.
	for _, t := range targets {
		usersProcessed[t.sid] = true
		hivesWithData++
		p.parseKeyNode(t.keyNode, "", "", t.sid, t.hiveName, &entries, advance)
		t.file.Close()
	}

	if len(entries) == 0 {
		stats["users_processed"] = len(usersProcessed)
		stats["hives_with_data"] = hivesWithData
		stats["total_entries"] = 0
		return nil, stats, errs
	}

	csvPath := filepath.Join(outDir, "shellbags.csv")
	if err := writeShellbagsCSV(csvPath, entries); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write shellbags.csv: %w", err))
	}

	stats["users_processed"] = len(usersProcessed)
	stats["hives_with_data"] = hivesWithData
	stats["total_entries"] = len(entries)

	return []string{csvPath}, stats, errs
}

func countSubkeys(node *regparser.CM_KEY_NODE) int {
	count := len(node.Subkeys())
	for _, sub := range node.Subkeys() {
		count += countSubkeys(sub)
	}
	return count
}

func (p *ShellBagsParser) parseKeyNode(node *regparser.CM_KEY_NODE, parentPath string, mruPath string, sid string, hiveName string, entries *[]shellbagEntry, advance func()) {
	var numberedValues []string
	for _, v := range node.Values() {
		name := v.ValueName()
		if name == "MRUListEx" || name == "NodeSlots" || name == "" {
			continue
		}
		if isNumber(name) {
			numberedValues = append(numberedValues, name)
		}
	}

	for _, valName := range numberedValues {
		for _, v := range node.Values() {
			if v.ValueName() == valName {
				data := v.ValueData().Data
				if len(data) < 2 {
					continue
				}
				cb := binary.LittleEndian.Uint16(data[0:2])
				if int(cb) > len(data) || cb < 2 {
					continue
				}

				itemData := data[0:cb]
				parsedName := parseShellItemName(itemData)

				currentPath := parentPath
				if parsedName != "" {
					if currentPath == "" {
						currentPath = parsedName
					} else {
						if strings.HasSuffix(currentPath, "\\") {
							currentPath = currentPath + parsedName
						} else {
							currentPath = currentPath + "\\" + parsedName
						}
					}
				}

				childKey := findSubkey(node, valName)
				childLastWrite := ""
				var nextMruPath string
				if mruPath == "" {
					nextMruPath = valName
				} else {
					nextMruPath = mruPath + "\\" + valName
				}

				if childKey != nil {
					childLastWrite = lastWriteStr(childKey)
				}

				*entries = append(*entries, shellbagEntry{
					SID:          sid,
					SourceHive:   hiveName,
					MRUPath:      `BagMRU\` + nextMruPath,
					FolderPath:   currentPath,
					LastWriteUTC: childLastWrite,
					SubkeyIndex:  valName,
				})

				if childKey != nil {
					p.parseKeyNode(childKey, currentPath, nextMruPath, sid, hiveName, entries, advance)
				}
			}
		}
	}
	advance()
}

func parseShellItemName(data []byte) string {
	if len(data) < 3 {
		return ""
	}
	itemType := data[2]

	switch {
	case itemType == 0x1F:
		// Root folder (GUID)
		if len(data) >= 20 {
			guidBytes := data[4:20]
			guidStr := formatGUID(guidBytes)
			if name, ok := wellKnownShellGUIDs[guidStr]; ok {
				return name
			}
			return "{" + guidStr + "}"
		}
		return "RootFolder"

	case itemType == 0x2F || itemType == 0x2E:
		// Drive / Volume
		return readNullTerminatedString(data[3:])

	case itemType >= 0x30 && itemType <= 0x39:
		// File system entry
		asciiName := ""
		if len(data) >= 14 {
			asciiName = readNullTerminatedString(data[14:])
		}

		unicodeName := ""
		nullIndex := -1
		for i := 14; i < len(data); i++ {
			if data[i] == 0 {
				nullIndex = i
				break
			}
		}
		if nullIndex != -1 {
			extOffset := nullIndex + 1
			if extOffset < len(data) && data[extOffset] == 0 {
				extOffset++
			}
			for extOffset+8 <= len(data) {
				extSize := binary.LittleEndian.Uint16(data[extOffset : extOffset+2])
				if extSize < 8 || extOffset+int(extSize) > len(data) {
					break
				}
				signature := binary.LittleEndian.Uint16(data[extOffset+6 : extOffset+8])
				if signature == 0xbeef {
					version := binary.LittleEndian.Uint16(data[extOffset+2 : extOffset+4])
					extData := data[extOffset : extOffset+int(extSize)]

					var uOffset int
					if version >= 7 {
						if len(extData) >= 18 {
							longNameOffset := binary.LittleEndian.Uint16(extData[16:18])
							if longNameOffset > 0 && int(longNameOffset) < len(extData) {
								uOffset = int(longNameOffset)
							}
						}
					} else if version == 3 {
						uOffset = 28
					}

					if uOffset > 0 && uOffset < len(extData) {
						unicodeName = readNullTerminatedUTF16LE(extData[uOffset:])
					}
					break
				}
				extOffset += int(extSize)
			}
		}

		if unicodeName != "" {
			return unicodeName
		}
		return asciiName
	}

	// Fallback
	if len(data) >= 14 {
		if s := readNullTerminatedString(data[14:]); s != "" {
			return s
		}
	}
	return ""
}

func readNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

func readNullTerminatedUTF16LE(data []byte) string {
	var runes []rune
	for i := 0; i+1 < len(data); i += 2 {
		r := uint16(data[i]) | (uint16(data[i+1]) << 8)
		if r == 0 {
			break
		}
		runes = append(runes, rune(r))
	}
	return string(runes)
}

func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}

func findSubkey(node *regparser.CM_KEY_NODE, name string) *regparser.CM_KEY_NODE {
	for _, sub := range node.Subkeys() {
		if strings.EqualFold(sub.Name(), name) {
			return sub
		}
	}
	return nil
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func writeShellbagsCSV(path string, entries []shellbagEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"sid", "source_hive", "mru_path", "folder_path", "last_write_utc", "subkey_index",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, e := range entries {
		if err := w.Write([]string{
			e.SID, e.SourceHive, e.MRUPath, csvSafe(e.FolderPath), e.LastWriteUTC, e.SubkeyIndex,
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
