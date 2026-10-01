package analyzer

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"www.velocidex.com/golang/regparser"
)

// AmcacheParser parses modern and legacy AmCache.hve registry hives
// and extracts files, programs, drivers, and shortcut metadata.
type AmcacheParser struct{}

func (p *AmcacheParser) Name() string { return "amcache" }

type amcacheFile struct {
	LastWriteUTC      string
	ProgramID         string
	FileID            string
	Path              string
	Name              string
	OriginalFileName  string
	Publisher         string
	Version           string
	BinFileVersion    string
	ProductName       string
	ProductVersion    string
	BinProductVersion string
	IsOsComponent     string
	BinaryType        string
	LinkDate          string
	Size              string
	Language          string
	Usn               string
	SourceKey         string
}

type amcacheProgram struct {
	LastWriteUTC      string
	ProgramID         string
	ProgramInstanceID string
	Name              string
	Version           string
	Publisher         string
	Language          string
	Source            string
	RootDirPath       string
	StoreAppType      string
	ManifestPath      string
	PackageFullName   string
	SourceKey         string
}

type amcacheDriver struct {
	LastWriteUTC            string
	DriverName              string
	Inf                     string
	DriverVersion           string
	Product                 string
	ProductVersion          string
	WdfVersion              string
	DriverCompany           string
	DriverPackageStrongName string
	Service                 string
	DriverInBox             string
	DriverSigned            string
	DriverIsKernelMode      string
	DriverID                string
	DriverLastWriteTime     string
	DriverType              string
	DriverTimeStamp         string
	DriverCheckSum          string
	ImageSize               string
	SourceKey               string
}

type amcacheShortcut struct {
	LastWriteUTC       string
	ShortcutPath       string
	ShortcutTargetPath string
	ShortcutAumid      string
	ShortcutProgramID  string
	SourceKey          string
}

func (p *AmcacheParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error

	amcacheGlob := filepath.Join(caseDir, "modules", "*_amcache_collection", "Amcache.hve")
	matches, err := filepath.Glob(amcacheGlob)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("glob amcache: %w", err)}
	}
	if len(matches) == 0 {
		return nil, stats, nil
	}
	amcachePath := matches[0]

	f, err := os.Open(amcachePath)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("open Amcache.hve: %w", err)}
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("parse Amcache.hve registry: %w", err)}
	}

	root := reg.OpenKey("Root")
	if root == nil {
		return nil, stats, []error{fmt.Errorf("Root key not found in Amcache.hve")}
	}

	// Output directory
	outDir := filepath.Join(labReportDir, "amcache")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, []error{fmt.Errorf("create amcache output dir: %w", err)}
	}

	// Find key nodes to parse
	appFileKey := reg.OpenKey(`Root\InventoryApplicationFile`)
	appKey := reg.OpenKey(`Root\InventoryApplication`)
	driverKey := reg.OpenKey(`Root\InventoryDriverBinary`)
	shortcutKey := reg.OpenKey(`Root\InventoryApplicationShortcut`)

	legacyFileKey := reg.OpenKey(`Root\File`)
	legacyProgKey := reg.OpenKey(`Root\Programs`)

	// Count total keys for progress reporting
	totalKeys := 0
	if appFileKey != nil {
		totalKeys += len(appFileKey.Subkeys())
	}
	if appKey != nil {
		totalKeys += len(appKey.Subkeys())
	}
	if driverKey != nil {
		totalKeys += len(driverKey.Subkeys())
	}
	if shortcutKey != nil {
		totalKeys += len(shortcutKey.Subkeys())
	}
	if legacyFileKey != nil {
		for _, vol := range legacyFileKey.Subkeys() {
			totalKeys += len(vol.Subkeys())
		}
	}
	if legacyProgKey != nil {
		totalKeys += len(legacyProgKey.Subkeys())
	}

	doneKeys := 0
	advance := func() {
		doneKeys++
		if report != nil {
			report(doneKeys, totalKeys)
		}
	}

	var files []amcacheFile
	var programs []amcacheProgram
	var drivers []amcacheDriver
	var shortcuts []amcacheShortcut

	// 1. Parse Root\InventoryApplicationFile (Modern Files)
	if appFileKey != nil {
		for _, sub := range appFileKey.Subkeys() {
			path := getValByNameStr(sub, "LowerCaseLongPath")
			name := getValByNameStr(sub, "Name")
			// Filter out empty paths to avoid cluttering results
			if path == "" && name == "" {
				advance()
				continue
			}

			files = append(files, amcacheFile{
				LastWriteUTC:      lastWriteStr(sub),
				ProgramID:         getValByNameStr(sub, "ProgramId"),
				FileID:            getValByNameStr(sub, "FileId"),
				Path:              path,
				Name:              name,
				OriginalFileName:  getValByNameStr(sub, "OriginalFileName"),
				Publisher:         getValByNameStr(sub, "Publisher"),
				Version:           getValByNameStr(sub, "Version"),
				BinFileVersion:    getValByNameStr(sub, "BinFileVersion"),
				ProductName:       getValByNameStr(sub, "ProductName"),
				ProductVersion:    getValByNameStr(sub, "ProductVersion"),
				BinProductVersion: getValByNameStr(sub, "BinProductVersion"),
				IsOsComponent:     getValByNameStr(sub, "IsOsComponent"),
				BinaryType:        getValByNameStr(sub, "BinaryType"),
				LinkDate:          getValByNameStr(sub, "LinkDate"),
				Size:              getValByNameStr(sub, "Size"),
				Language:          getValByNameStr(sub, "Language"),
				Usn:               getValByNameStr(sub, "Usn"),
				SourceKey:         `Root\InventoryApplicationFile`,
			})
			advance()
		}
	}

	// 2. Parse Root\InventoryApplication (Modern Programs)
	if appKey != nil {
		for _, sub := range appKey.Subkeys() {
			programs = append(programs, amcacheProgram{
				LastWriteUTC:      lastWriteStr(sub),
				ProgramID:         getValByNameStr(sub, "ProgramId"),
				ProgramInstanceID: getValByNameStr(sub, "ProgramInstanceId"),
				Name:              getValByNameStr(sub, "Name"),
				Version:           getValByNameStr(sub, "Version"),
				Publisher:         getValByNameStr(sub, "Publisher"),
				Language:          getValByNameStr(sub, "Language"),
				Source:            getValByNameStr(sub, "Source"),
				RootDirPath:       getValByNameStr(sub, "RootDirPath"),
				StoreAppType:      getValByNameStr(sub, "StoreAppType"),
				ManifestPath:      getValByNameStr(sub, "ManifestPath"),
				PackageFullName:   getValByNameStr(sub, "PackageFullName"),
				SourceKey:         `Root\InventoryApplication`,
			})
			advance()
		}
	}

	// 3. Parse Root\InventoryDriverBinary (Modern Drivers)
	if driverKey != nil {
		for _, sub := range driverKey.Subkeys() {
			drivers = append(drivers, amcacheDriver{
				LastWriteUTC:            lastWriteStr(sub),
				DriverName:              getValByNameStr(sub, "DriverName"),
				Inf:                     getValByNameStr(sub, "Inf"),
				DriverVersion:           getValByNameStr(sub, "DriverVersion"),
				Product:                 getValByNameStr(sub, "Product"),
				ProductVersion:          getValByNameStr(sub, "ProductVersion"),
				WdfVersion:              getValByNameStr(sub, "WdfVersion"),
				DriverCompany:           getValByNameStr(sub, "DriverCompany"),
				DriverPackageStrongName: getValByNameStr(sub, "DriverPackageStrongName"),
				Service:                 getValByNameStr(sub, "Service"),
				DriverInBox:             getValByNameStr(sub, "DriverInBox"),
				DriverSigned:            getValByNameStr(sub, "DriverSigned"),
				DriverIsKernelMode:      getValByNameStr(sub, "DriverIsKernelMode"),
				DriverID:                getValByNameStr(sub, "DriverId"),
				DriverLastWriteTime:     getValByNameStr(sub, "DriverLastWriteTime"),
				DriverType:              getValByNameStr(sub, "DriverType"),
				DriverTimeStamp:         getValByNameStr(sub, "DriverTimeStamp"),
				DriverCheckSum:          getValByNameStr(sub, "DriverCheckSum"),
				ImageSize:               getValByNameStr(sub, "ImageSize"),
				SourceKey:               `Root\InventoryDriverBinary`,
			})
			advance()
		}
	}

	// 4. Parse Root\InventoryApplicationShortcut (Modern Shortcuts)
	if shortcutKey != nil {
		for _, sub := range shortcutKey.Subkeys() {
			shortcuts = append(shortcuts, amcacheShortcut{
				LastWriteUTC:       lastWriteStr(sub),
				ShortcutPath:       getValByNameStr(sub, "ShortcutPath"),
				ShortcutTargetPath: getValByNameStr(sub, "ShortcutTargetPath"),
				ShortcutAumid:      getValByNameStr(sub, "ShortcutAumid"),
				ShortcutProgramID:  getValByNameStr(sub, "ShortcutProgramId"),
				SourceKey:          `Root\InventoryApplicationShortcut`,
			})
			advance()
		}
	}

	// 5. Parse Root\File (Legacy Files Fallback)
	if legacyFileKey != nil {
		for _, vol := range legacyFileKey.Subkeys() {
			volName := vol.Name()
			for _, sub := range vol.Subkeys() {
				path := getValByNameStr(sub, "15")
				name := getValByNameStr(sub, "0")
				if path == "" && name == "" {
					advance()
					continue
				}

				// Normalize hash
				rawHash := getValByNameStr(sub, "7")
				normalizedHash := strings.TrimPrefix(strings.ToLower(rawHash), "0000")

				files = append(files, amcacheFile{
					LastWriteUTC:      lastWriteStr(sub),
					ProgramID:         "", // N/A in legacy File key
					FileID:            normalizedHash,
					Path:              path,
					Name:              name,
					OriginalFileName:  "",
					Publisher:         getValByNameStr(sub, "2"),
					Version:           getValByNameStr(sub, "3"),
					BinFileVersion:    "",
					ProductName:       getValByNameStr(sub, "1"),
					ProductVersion:    getValByNameStr(sub, "3"),
					BinProductVersion: "",
					IsOsComponent:     "",
					BinaryType:        "",
					LinkDate:          getValByNameStr(sub, "12"),
					Size:              getValByNameStr(sub, "6"),
					Language:          "",
					Usn:               "",
					SourceKey:         `Root\File\` + volName,
				})
				advance()
			}
		}
	}

	// 6. Parse Root\Programs (Legacy Programs Fallback)
	if legacyProgKey != nil {
		for _, sub := range legacyProgKey.Subkeys() {
			programs = append(programs, amcacheProgram{
				LastWriteUTC:      lastWriteStr(sub),
				ProgramID:         getValByNameStr(sub, "10"),
				ProgramInstanceID: "",
				Name:              getValByNameStr(sub, "0"),
				Version:           getValByNameStr(sub, "1"),
				Publisher:         getValByNameStr(sub, "2"),
				Language:          getValByNameStr(sub, "f"),
				Source:            "",
				RootDirPath:       getValByNameStr(sub, "d"),
				StoreAppType:      "",
				ManifestPath:      "",
				PackageFullName:   "",
				SourceKey:         `Root\Programs`,
			})
			advance()
		}
	}

	var outputs []string

	// Write CSVs if data exists
	if len(files) > 0 {
		csvPath := filepath.Join(outDir, "amcache_files.csv")
		if err := writeFilesCSV(csvPath, files); err != nil {
			errs = append(errs, fmt.Errorf("write amcache_files.csv: %w", err))
		} else {
			outputs = append(outputs, csvPath)
		}
	}

	if len(programs) > 0 {
		csvPath := filepath.Join(outDir, "amcache_programs.csv")
		if err := writeProgramsCSV(csvPath, programs); err != nil {
			errs = append(errs, fmt.Errorf("write amcache_programs.csv: %w", err))
		} else {
			outputs = append(outputs, csvPath)
		}
	}

	if len(drivers) > 0 {
		csvPath := filepath.Join(outDir, "amcache_drivers.csv")
		if err := writeDriversCSV(csvPath, drivers); err != nil {
			errs = append(errs, fmt.Errorf("write amcache_drivers.csv: %w", err))
		} else {
			outputs = append(outputs, csvPath)
		}
	}

	if len(shortcuts) > 0 {
		csvPath := filepath.Join(outDir, "amcache_shortcuts.csv")
		if err := writeShortcutsCSV(csvPath, shortcuts); err != nil {
			errs = append(errs, fmt.Errorf("write amcache_shortcuts.csv: %w", err))
		} else {
			outputs = append(outputs, csvPath)
		}
	}

	stats["files_parsed"] = len(files)
	stats["programs_parsed"] = len(programs)
	stats["drivers_parsed"] = len(drivers)
	stats["shortcuts_parsed"] = len(shortcuts)

	return outputs, stats, errs
}

// lastWriteStr converts key modification time to a string representation.
func lastWriteStr(k *regparser.CM_KEY_NODE) string {
	if lw := k.LastWriteTime(); lw != nil {
		return lw.Time.Format(time.RFC3339)
	}
	return ""
}

// getValByNameStr retrieves a named value's string representation.
func getValByNameStr(k *regparser.CM_KEY_NODE, name string) string {
	for _, v := range k.Values() {
		if strings.EqualFold(v.ValueName(), name) {
			return getValueStr(v)
		}
	}
	return ""
}

// getValueStr translates CM_KEY_VALUE data to a normalized string.
func getValueStr(v *regparser.CM_KEY_VALUE) string {
	vd := v.ValueData()
	switch vd.Type {
	case 1, 2: // REG_SZ, REG_EXPAND_SZ
		return strings.TrimSpace(strings.TrimRight(vd.String, "\x00"))
	case 4, 11: // REG_DWORD, REG_QWORD
		return strconv.FormatUint(vd.Uint64, 10)
	case 7: // REG_MULTI_SZ
		return strings.Join(vd.MultiSz, "; ")
	case 3: // REG_BINARY
		// For short binary values (≤64 bytes) emit a lowercase hex string, which
		// is the correct display format for SHA-1/SHA-256 file hashes stored in
		// AmCache (FileId field). For larger blobs fall back to a length hint.
		if len(vd.Data) <= 64 {
			return hex.EncodeToString(vd.Data)
		}
		return fmt.Sprintf("(binary, len=%d)", len(vd.Data))
	default:
		if vd.String != "" {
			return strings.TrimSpace(strings.TrimRight(vd.String, "\x00"))
		}
		return ""
	}
}

// ---- CSV Serialization ----

func writeFilesCSV(path string, rows []amcacheFile) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"last_write_utc", "program_id", "file_id", "path", "name",
		"original_file_name", "publisher", "version", "bin_file_version",
		"product_name", "product_version", "bin_product_version",
		"is_os_component", "binary_type", "link_date", "size",
		"language", "usn", "source_key",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range rows {
		if err := w.Write([]string{
			r.LastWriteUTC, r.ProgramID, r.FileID, csvSafe(r.Path), csvSafe(r.Name),
			csvSafe(r.OriginalFileName), csvSafe(r.Publisher), r.Version, r.BinFileVersion,
			csvSafe(r.ProductName), r.ProductVersion, r.BinProductVersion,
			r.IsOsComponent, r.BinaryType, r.LinkDate, r.Size,
			r.Language, r.Usn, r.SourceKey,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeProgramsCSV(path string, rows []amcacheProgram) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"last_write_utc", "program_id", "program_instance_id", "name", "version",
		"publisher", "language", "source", "root_dir_path", "store_app_type",
		"manifest_path", "package_full_name", "source_key",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range rows {
		if err := w.Write([]string{
			r.LastWriteUTC, r.ProgramID, r.ProgramInstanceID, csvSafe(r.Name), r.Version,
			csvSafe(r.Publisher), r.Language, r.Source, csvSafe(r.RootDirPath),
			r.StoreAppType, csvSafe(r.ManifestPath), csvSafe(r.PackageFullName), r.SourceKey,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeDriversCSV(path string, rows []amcacheDriver) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"last_write_utc", "driver_name", "inf", "driver_version", "product",
		"product_version", "wdf_version", "driver_company", "driver_package_strong_name",
		"service", "driver_in_box", "driver_signed", "driver_is_kernel_mode",
		"driver_id", "driver_last_write_time", "driver_type", "driver_time_stamp",
		"driver_check_sum", "image_size", "source_key",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range rows {
		if err := w.Write([]string{
			r.LastWriteUTC, csvSafe(r.DriverName), csvSafe(r.Inf), r.DriverVersion, csvSafe(r.Product),
			r.ProductVersion, r.WdfVersion, csvSafe(r.DriverCompany), csvSafe(r.DriverPackageStrongName),
			csvSafe(r.Service), r.DriverInBox, r.DriverSigned, r.DriverIsKernelMode,
			r.DriverID, r.DriverLastWriteTime, r.DriverType, r.DriverTimeStamp,
			r.DriverCheckSum, r.ImageSize, r.SourceKey,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeShortcutsCSV(path string, rows []amcacheShortcut) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"last_write_utc", "shortcut_path", "shortcut_target_path", "shortcut_aumid",
		"shortcut_program_id", "source_key",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range rows {
		if err := w.Write([]string{
			r.LastWriteUTC, csvSafe(r.ShortcutPath), csvSafe(r.ShortcutTargetPath), csvSafe(r.ShortcutAumid),
			r.ShortcutProgramID, r.SourceKey,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}
