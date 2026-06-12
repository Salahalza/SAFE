package analyzer

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ProcessMemoryParser reads the raw region dumps collected by the
// process_memory_inspection module and performs the interpretation the
// collection module deliberately does NOT do on the target: RWX triage,
// PE-carving, and string/IOC extraction.
//
// The collection module is collect-only by design (see the 2026-06-12e
// design journal): on-target it writes raw region bytes plus two index CSVs
// and makes zero judgement. All of that judgement lives here, lab-side, so
// findings are reproducible instead of one-shot on a hostile host.
//
// Output (under lab_report/process_memory/):
//   - regions_triage.csv  — one row per dumped region, enriched with a triage
//     tier, PE-header detection, string counts, and IOC-hit counts. This is
//     the analyst's at-a-glance index into the raw blobs.
//   - carved_pe/          — PE images carved out of regions that contain a
//     valid MZ/PE header (manually-mapped / reflectively-loaded code).
//   - strings/            — extracted ASCII + UTF-16LE strings, one file per
//     dumped region, each capped (see stringsFileCap).
//   - summary.txt         — human-readable triage summary.
type ProcessMemoryParser struct{}

func (p *ProcessMemoryParser) Name() string { return "process_memory" }

// Tuning constants.
const (
	// minStringLen is the minimum run length for an extracted string. 6 is the
	// common forensic default — short enough to catch API names, long enough to
	// keep noise down.
	minStringLen = 6

	// stringsFileCap bounds a single region's strings .txt file. A real
	// endpoint_deep run can dump GB of memory; without a cap one pathological
	// region could produce an enormous text file. 256 KiB of strings text per
	// region is generous for triage; truncation is recorded in the file and in
	// the note column. Counts in regions_triage.csv are NOT capped — they
	// always reflect the full region.
	stringsFileCap = 256 * 1024

	// maxPEsPerRegion caps how many PE images we carve out of one region, a
	// backstop against a blob full of MZ-looking byte noise.
	maxPEsPerRegion = 16
)

// region mirrors one row of the module's regions.csv.
type region struct {
	pid        string
	name       string
	baseAddr   string
	regionSize string
	state      string
	protect    string
	typ        string
	dumped     bool
	bytes      string
	blobPath   string // relative to the module dir, forward-slashed
	note       string
}

// triagedRegion is a region enriched with this parser's findings.
type triagedRegion struct {
	region
	tier         string // HIGH / NOTABLE / LOW
	isRWX        bool
	hasPE        bool
	peMachine    string
	peIsDLL      bool
	asciiStrings int
	utf16Strings int
	iocHits      int
	carvedPath   string // relative to lab_report, "" if none
	stringsPath  string // relative to lab_report, "" if none
	analysisNote string
}

func (p *ProcessMemoryParser) Parse(caseDir, labReportDir string) ([]string, ParseStats, []error) {
	stats := ParseStats{}

	// Locate the process_memory_inspection module output directory.
	glob := filepath.Join(caseDir, "modules", "*_process_memory_inspection")
	matches, err := filepath.Glob(glob)
	if err != nil {
		return nil, nil, []error{fmt.Errorf("glob process_memory_inspection dir: %w", err)}
	}
	// Absent module is the common case (PMI is opt-in; rapid_triage never has
	// it). Return no outputs and no errors so the run reports "skipped", exactly
	// what analyzer.go documents that status for — not "failed".
	if len(matches) == 0 {
		return nil, stats, nil
	}
	moduleDir := matches[0]

	regions, err := readRegionsCSV(filepath.Join(moduleDir, "regions.csv"))
	if err != nil {
		return nil, nil, []error{fmt.Errorf("read regions.csv: %w", err)}
	}

	outDir := filepath.Join(labReportDir, "process_memory")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, nil, []error{fmt.Errorf("create output dir: %w", err)}
	}
	carvedDir := filepath.Join(outDir, "carved_pe")
	stringsDir := filepath.Join(outDir, "strings")

	var errs []error
	var triaged []triagedRegion

	for _, r := range regions {
		if !r.dumped || r.blobPath == "" {
			// A region the module recorded but could not read (read error). It
			// still belongs in the triage index, just with no analysis.
			tr := triagedRegion{region: r, tier: "LOW", analysisNote: "not dumped"}
			tr.isRWX = strings.EqualFold(r.protect, "RWX")
			triaged = append(triaged, tr)
			continue
		}

		blobAbs := filepath.Join(moduleDir, filepath.FromSlash(r.blobPath))
		data, rerr := os.ReadFile(blobAbs)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("%s: read blob: %w", r.blobPath, rerr))
			tr := triagedRegion{region: r, tier: "LOW", analysisNote: "blob unreadable"}
			triaged = append(triaged, tr)
			continue
		}

		tr := analyzeRegion(r, data)

		// PE-carve: write each detected PE image to its own file.
		pes := findPEs(data)
		if len(pes) > 0 {
			tr.hasPE = true
			tr.peMachine = machineString(pes[0].machine)
			tr.peIsDLL = pes[0].isDLL
			if cerr := os.MkdirAll(carvedDir, 0o755); cerr != nil {
				errs = append(errs, fmt.Errorf("create carved_pe dir: %w", cerr))
			} else if rel, cerr := carvePEs(carvedDir, labReportDir, r, data, pes); cerr != nil {
				errs = append(errs, fmt.Errorf("%s: carve pe: %w", r.blobPath, cerr))
			} else {
				tr.carvedPath = rel
			}
		}

		// Strings + IOC extraction.
		ascii, utf16 := extractStrings(data, minStringLen)
		tr.asciiStrings = len(ascii)
		tr.utf16Strings = len(utf16)
		iocs := scanIOCs(ascii, utf16)
		tr.iocHits = iocs.total

		if serr := os.MkdirAll(stringsDir, 0o755); serr != nil {
			errs = append(errs, fmt.Errorf("create strings dir: %w", serr))
		} else if rel, truncated, serr := writeStringsFile(stringsDir, labReportDir, r, ascii, utf16); serr != nil {
			errs = append(errs, fmt.Errorf("%s: write strings: %w", r.blobPath, serr))
		} else {
			tr.stringsPath = rel
			if truncated {
				tr.analysisNote = appendNote(tr.analysisNote, fmt.Sprintf("strings truncated at %d KiB", stringsFileCap/1024))
			}
		}

		// Final tier now that PE/IOC findings are known.
		tr.tier = triageTier(tr)
		triaged = append(triaged, tr)
	}

	// Write the triage CSV.
	csvPath := filepath.Join(outDir, "regions_triage.csv")
	if werr := writeTriageCSV(csvPath, triaged); werr != nil {
		return nil, stats, append(errs, fmt.Errorf("write regions_triage.csv: %w", werr))
	}
	outputs := []string{csvPath}

	// Write the human-readable summary, pulling per-process open results from
	// the module's processes.csv for context.
	procSummary := readProcessSummary(filepath.Join(moduleDir, "processes.csv"))
	summaryPath := filepath.Join(outDir, "summary.txt")
	if werr := writeSummary(summaryPath, triaged, procSummary); werr != nil {
		errs = append(errs, fmt.Errorf("write summary.txt: %w", werr))
	} else {
		outputs = append(outputs, summaryPath)
	}

	// Stats.
	high, notable, peCount, iocRegions, stringFiles := 0, 0, 0, 0, 0
	for _, t := range triaged {
		switch t.tier {
		case "HIGH":
			high++
		case "NOTABLE":
			notable++
		}
		if t.hasPE {
			peCount++
		}
		if t.iocHits > 0 {
			iocRegions++
		}
		if t.stringsPath != "" {
			stringFiles++
		}
	}
	stats["regions_total"] = len(triaged)
	stats["regions_high"] = high
	stats["regions_notable"] = notable
	stats["pe_carved"] = peCount
	stats["ioc_regions"] = iocRegions
	stats["strings_files"] = stringFiles

	return outputs, stats, errs
}

// analyzeRegion seeds a triagedRegion from the raw region row. PE/string/IOC
// findings are filled in by the caller.
func analyzeRegion(r region, _ []byte) triagedRegion {
	return triagedRegion{
		region: r,
		isRWX:  strings.EqualFold(r.protect, "RWX"),
	}
}

// triageTier assigns the review priority for a region.
//
//   - HIGH:    RWX private memory (the classic injection signature) OR a region
//     carrying a valid PE header (manually-mapped / reflectively-loaded code).
//   - NOTABLE: an executable region with IOC hits but no PE header — worth a
//     look (e.g. RX-private shellcode-ish page referencing URLs/APIs).
//   - LOW:     executable private memory with nothing else notable (commonly
//     benign JIT from browsers / .NET, which the module's filter surfaces).
func triageTier(t triagedRegion) string {
	if t.isRWX || t.hasPE {
		return "HIGH"
	}
	if t.iocHits > 0 {
		return "NOTABLE"
	}
	return "LOW"
}

// ---- regions.csv reading -------------------------------------------------

func readRegionsCSV(path string) ([]region, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1 // tolerate ragged rows
	rows, err := rd.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	// Map columns by header name so we are robust to column reordering.
	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[strings.TrimSpace(h)] = i
	}
	get := func(row []string, key string) string {
		i, ok := idx[key]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}

	var regions []region
	for _, row := range rows[1:] {
		r := region{
			pid:        get(row, "pid"),
			name:       get(row, "name"),
			baseAddr:   get(row, "base_addr"),
			regionSize: get(row, "region_size"),
			state:      get(row, "state"),
			protect:    get(row, "protect"),
			typ:        get(row, "type"),
			bytes:      get(row, "bytes"),
			blobPath:   get(row, "blob_path"),
			note:       get(row, "note"),
		}
		r.dumped, _ = strconv.ParseBool(get(row, "dumped"))
		regions = append(regions, r)
	}
	return regions, nil
}

// ---- PE detection / carving ----------------------------------------------

// peHit describes a valid PE header found inside a region blob.
type peHit struct {
	offset    int    // offset of the MZ header within the blob
	machine   uint16 // COFF Machine field
	isDLL     bool   // IMAGE_FILE_DLL in Characteristics
	imageSize uint32 // SizeOfImage from the optional header (0 if unavailable)
}

const imageFileDLL = 0x2000

// knownMachines is the allow-list of COFF Machine values we accept. Requiring a
// known machine rejects the great majority of incidental "MZ" byte sequences
// that are not real PE headers.
var knownMachines = map[uint16]string{
	0x014c: "I386",
	0x8664: "AMD64",
	0xaa64: "ARM64",
	0x01c0: "ARM",
	0x01c4: "ARMNT",
	0x0200: "IA64",
}

func machineString(m uint16) string {
	if s, ok := knownMachines[m]; ok {
		return s
	}
	return fmt.Sprintf("0x%x", m)
}

// findPEs scans a blob for valid MZ/PE headers. It validates the DOS stub's
// e_lfanew pointer, the "PE\0\0" signature, and a known Machine value before
// accepting a hit, which keeps false positives low.
func findPEs(data []byte) []peHit {
	var hits []peHit
	for i := 0; i+1 < len(data); i++ {
		if data[i] != 'M' || data[i+1] != 'Z' {
			continue
		}
		if hit, ok := validatePE(data, i); ok {
			hits = append(hits, hit)
			if len(hits) >= maxPEsPerRegion {
				break
			}
			// Skip past this image to avoid re-matching MZ bytes inside it.
			if hit.imageSize > 0 {
				i += int(hit.imageSize) - 1
			}
		}
	}
	return hits
}

func validatePE(data []byte, off int) (peHit, bool) {
	// Need the DOS header through e_lfanew (offset 0x3C, 4 bytes).
	if off+0x40 > len(data) {
		return peHit{}, false
	}
	eLfanew := int(binary.LittleEndian.Uint32(data[off+0x3C : off+0x40]))
	peOff := off + eLfanew
	// Need the PE signature (4) + COFF file header (20) = 24 bytes.
	if eLfanew <= 0 || peOff+24 > len(data) {
		return peHit{}, false
	}
	if data[peOff] != 'P' || data[peOff+1] != 'E' || data[peOff+2] != 0 || data[peOff+3] != 0 {
		return peHit{}, false
	}
	machine := binary.LittleEndian.Uint16(data[peOff+4 : peOff+6])
	if _, ok := knownMachines[machine]; !ok {
		return peHit{}, false
	}
	characteristics := binary.LittleEndian.Uint16(data[peOff+22 : peOff+24])

	// SizeOfImage lives at optional-header offset 56. The optional header starts
	// at peOff+24. Read it when present; it is the same offset for PE32/PE32+.
	var imageSize uint32
	if sz := peOff + 24 + 60; sz <= len(data) {
		imageSize = binary.LittleEndian.Uint32(data[peOff+24+56 : peOff+24+60])
	}

	return peHit{
		offset:    off,
		machine:   machine,
		isDLL:     characteristics&imageFileDLL != 0,
		imageSize: imageSize,
	}, true
}

// carvePEs writes each detected PE image to its own file under carvedDir and
// returns the path of the first carve, relative to labReportDir. Because the
// collection module dumps individual executable regions (not whole images), a
// region often contains only part of an image; we carve what is present and
// note when it is partial.
func carvePEs(carvedDir, labReportDir string, r region, data []byte, pes []peHit) (string, error) {
	var firstRel string
	for n, pe := range pes {
		end := len(data)
		if pe.imageSize > 0 && pe.offset+int(pe.imageSize) < end {
			end = pe.offset + int(pe.imageSize)
		}
		blob := data[pe.offset:end]

		suffix := ""
		if n > 0 {
			suffix = fmt.Sprintf("_%d", n)
		}
		fname := fmt.Sprintf("%s_%s_%s%s.bin", r.pid, sanitizeComponent(r.name), strings.TrimPrefix(r.baseAddr, "0x"), suffix)
		fpath := filepath.Join(carvedDir, fname)
		if err := os.WriteFile(fpath, blob, 0o644); err != nil {
			return firstRel, err
		}
		if firstRel == "" {
			rel, _ := filepath.Rel(labReportDir, fpath)
			firstRel = filepath.ToSlash(rel)
		}
	}
	return firstRel, nil
}

// ---- string extraction ---------------------------------------------------

// extractStrings returns printable ASCII and UTF-16LE strings of at least
// minLen runes. UTF-16LE is detected as printable-ASCII bytes interleaved with
// NUL — sufficient for the API names, paths, and URLs that matter for triage.
func extractStrings(data []byte, minLen int) (ascii, utf16 []string) {
	// ASCII.
	start := -1
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= minLen {
				ascii = append(ascii, string(data[start:i]))
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minLen {
		ascii = append(ascii, string(data[start:]))
	}

	// UTF-16LE: printable byte followed by 0x00.
	var run []byte
	for i := 0; i+1 < len(data); i += 2 {
		lo, hi := data[i], data[i+1]
		if hi == 0x00 && lo >= 0x20 && lo <= 0x7e {
			run = append(run, lo)
			continue
		}
		if len(run) >= minLen {
			utf16 = append(utf16, string(run))
		}
		run = run[:0]
	}
	if len(run) >= minLen {
		utf16 = append(utf16, string(run))
	}
	return ascii, utf16
}

// writeStringsFile writes a region's strings to stringsDir, capped at
// stringsFileCap bytes of text. Returns the path relative to labReportDir and
// whether output was truncated.
func writeStringsFile(stringsDir, labReportDir string, r region, ascii, utf16 []string) (string, bool, error) {
	fname := fmt.Sprintf("%s_%s_%s.txt", r.pid, sanitizeComponent(r.name), strings.TrimPrefix(r.baseAddr, "0x"))
	fpath := filepath.Join(stringsDir, fname)

	f, err := os.Create(fpath)
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	written := 0
	truncated := false
	writeLine := func(s string) bool {
		line := s + "\n"
		if written+len(line) > stringsFileCap {
			truncated = true
			return false
		}
		if _, werr := io.WriteString(f, line); werr != nil {
			err = werr
			return false
		}
		written += len(line)
		return true
	}

	hdr := fmt.Sprintf("# pid=%s name=%s base=%s protect=%s\n# --- ASCII (%d) ---\n",
		r.pid, r.name, r.baseAddr, r.protect, len(ascii))
	io.WriteString(f, hdr)
	written += len(hdr)

	for _, s := range ascii {
		if !writeLine(s) {
			break
		}
	}
	if !truncated {
		sec := fmt.Sprintf("# --- UTF-16LE (%d) ---\n", len(utf16))
		if written+len(sec) <= stringsFileCap {
			io.WriteString(f, sec)
			written += len(sec)
			for _, s := range utf16 {
				if !writeLine(s) {
					break
				}
			}
		} else {
			truncated = true
		}
	}
	if err != nil {
		return "", truncated, err
	}

	rel, _ := filepath.Rel(labReportDir, fpath)
	return filepath.ToSlash(rel), truncated, nil
}

// ---- IOC scanning --------------------------------------------------------

type iocResult struct {
	urls  []string
	ips   []string
	unc   []string
	apis  []string
	total int
}

var (
	reURL = regexp.MustCompile(`https?://[^\s"'<>|]+`)
	reIP  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reUNC = regexp.MustCompile(`\\\\[A-Za-z0-9._$-]+\\[^\s"'<>|]+`)
)

// suspiciousAPIs are injection / execution primitives whose presence in an
// unbacked executable region is worth surfacing. These are SHORTEST DISTINCTIVE
// STEMS, matched as case-sensitive substrings: "VirtualAlloc" also catches
// VirtualAllocEx/VirtualAllocExNuma, "LoadLibrary" catches the A/W/Ex variants,
// etc. Keeping stems (not every variant) both broadens coverage and avoids
// double-counting a single name (e.g. "VirtualAllocEx" matching twice). No stem
// is a substring of another, so each contributes at most one distinct hit.
var suspiciousAPIs = []string{
	"VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory",
	"CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx",
	"LoadLibrary", "GetProcAddress", "GetModuleHandle", "WinExec", "ShellExecute",
	"CreateProcess", "NtUnmapViewOfSection", "RtlMoveMemory", "RtlCopyMemory",
	"NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
	"ResumeThread",
}

// scanIOCs runs the IOC matchers over every extracted string and returns the
// distinct hits per category. Strings from both encodings are scanned.
func scanIOCs(ascii, utf16 []string) iocResult {
	var res iocResult
	seen := map[string]bool{}
	add := func(dst *[]string, v string) {
		if seen[v] {
			return
		}
		seen[v] = true
		*dst = append(*dst, v)
	}

	for _, s := range append(append([]string{}, ascii...), utf16...) {
		for _, m := range reURL.FindAllString(s, -1) {
			add(&res.urls, m)
		}
		for _, m := range reIP.FindAllString(s, -1) {
			if plausibleIP(m) {
				add(&res.ips, m)
			}
		}
		for _, m := range reUNC.FindAllString(s, -1) {
			add(&res.unc, m)
		}
		for _, api := range suspiciousAPIs {
			if strings.Contains(s, api) {
				add(&res.apis, api)
			}
		}
	}
	res.total = len(res.urls) + len(res.ips) + len(res.unc) + len(res.apis)
	return res
}

// plausibleIP rejects dotted-quads with any octet > 255 (the regex is loose).
func plausibleIP(s string) bool {
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n > 255 {
			return false
		}
	}
	return true
}

// ---- CSV / summary output ------------------------------------------------

func writeTriageCSV(path string, regions []triagedRegion) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"pid", "name", "base_addr", "region_size", "protect", "type", "bytes",
		"triage_tier", "is_rwx", "has_pe_header", "pe_machine", "pe_is_dll",
		"ascii_strings", "utf16_strings", "ioc_hits", "carved_pe_path",
		"strings_path", "note",
	}); err != nil {
		return err
	}

	for _, t := range regions {
		if err := w.Write([]string{
			t.pid, t.name, t.baseAddr, t.regionSize, t.protect, t.typ, t.bytes,
			t.tier, strconv.FormatBool(t.isRWX), strconv.FormatBool(t.hasPE),
			t.peMachine, strconv.FormatBool(t.peIsDLL),
			strconv.Itoa(t.asciiStrings), strconv.Itoa(t.utf16Strings),
			strconv.Itoa(t.iocHits), t.carvedPath, t.stringsPath, t.analysisNote,
		}); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}

// processSummary holds open-result counts read from the module's processes.csv.
type processSummary struct {
	total   int
	opened  int
	denied  int
	skipped int
}

// readProcessSummary best-effort reads the module's processes.csv for context
// in the summary. A missing/unreadable file is not fatal — it just means the
// summary omits the process-level breakdown.
func readProcessSummary(path string) processSummary {
	var ps processSummary
	f, err := os.Open(path)
	if err != nil {
		return ps
	}
	defer f.Close()

	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	rows, err := rd.ReadAll()
	if err != nil || len(rows) == 0 {
		return ps
	}
	openCol := -1
	for i, h := range rows[0] {
		if strings.TrimSpace(h) == "open_result" {
			openCol = i
		}
	}
	if openCol < 0 {
		return ps
	}
	for _, row := range rows[1:] {
		if openCol >= len(row) {
			continue
		}
		ps.total++
		switch {
		case strings.HasPrefix(row[openCol], "opened"):
			ps.opened++
		case strings.HasPrefix(row[openCol], "denied"):
			ps.denied++
		case strings.HasPrefix(row[openCol], "skipped"):
			ps.skipped++
		}
	}
	return ps
}

func writeSummary(path string, regions []triagedRegion, ps processSummary) error {
	var b strings.Builder

	high, notable, low, peCount := 0, 0, 0, 0
	for _, t := range regions {
		switch t.tier {
		case "HIGH":
			high++
		case "NOTABLE":
			notable++
		default:
			low++
		}
		if t.hasPE {
			peCount++
		}
	}

	fmt.Fprintf(&b, "process_memory analyzer summary\n")
	fmt.Fprintf(&b, "===============================\n\n")
	if ps.total > 0 {
		fmt.Fprintf(&b, "Processes in snapshot: %d (%d opened, %d denied, %d skipped)\n",
			ps.total, ps.opened, ps.denied, ps.skipped)
	}
	fmt.Fprintf(&b, "Dumped regions analyzed: %d  (HIGH %d, NOTABLE %d, LOW %d)\n",
		len(regions), high, notable, low)
	fmt.Fprintf(&b, "PE headers carved: %d\n\n", peCount)

	// HIGH regions, called out individually — these are what the analyst opens
	// first.
	fmt.Fprintf(&b, "HIGH-tier regions (RWX or PE-bearing):\n")
	anyHigh := false
	for _, t := range regions {
		if t.tier != "HIGH" {
			continue
		}
		anyHigh = true
		reason := []string{}
		if t.isRWX {
			reason = append(reason, "RWX")
		}
		if t.hasPE {
			reason = append(reason, fmt.Sprintf("PE/%s", t.peMachine))
			if t.peIsDLL {
				reason[len(reason)-1] += " DLL"
			}
		}
		fmt.Fprintf(&b, "  pid %s %s @ %s  [%s]  ioc=%d  ascii=%d utf16=%d\n",
			t.pid, t.name, t.baseAddr, strings.Join(reason, ","),
			t.iocHits, t.asciiStrings, t.utf16Strings)
	}
	if !anyHigh {
		fmt.Fprintf(&b, "  (none)\n")
	}

	// NOTABLE regions (IOC-bearing, no PE/RWX).
	fmt.Fprintf(&b, "\nNOTABLE-tier regions (IOC hits, no PE/RWX):\n")
	anyNotable := false
	for _, t := range regions {
		if t.tier != "NOTABLE" {
			continue
		}
		anyNotable = true
		fmt.Fprintf(&b, "  pid %s %s @ %s  ioc=%d\n", t.pid, t.name, t.baseAddr, t.iocHits)
	}
	if !anyNotable {
		fmt.Fprintf(&b, "  (none)\n")
	}

	fmt.Fprintf(&b, "\nSee regions_triage.csv for the full per-region index, "+
		"carved_pe/ for extracted PE images, and strings/ for per-region strings.\n")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// ---- small helpers -------------------------------------------------------

// sanitizeComponent makes a process name safe as a filename component. Mirrors
// the collection module's sanitizeName so carved/strings filenames line up with
// the dumps/ directory names.
func sanitizeComponent(s string) string {
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func appendNote(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}