//go:build windows

package module

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Memory-region Type and State values from Win32 that x/sys/windows does not
// export (it only exports MEM_COMMIT / MEM_RESERVE).
const (
	memPrivate uint32 = 0x20000
	memMapped  uint32 = 0x40000
	memImage   uint32 = 0x1000000
	memFree    uint32 = 0x10000
)

// maxRegionBytes caps a single region dump so one pathological region (a
// process can hold a very large committed RWX block) cannot blow up the case
// folder. Larger regions are recorded in the index with their bytes truncated
// to this cap. Injected code / JIT pages are normally far under this.
const maxRegionBytes uintptr = 128 * 1024 * 1024 // 128 MiB

// processAccess is the rights set we request: VirtualQueryEx needs
// PROCESS_QUERY_INFORMATION, ReadProcessMemory needs PROCESS_VM_READ.
const processAccess = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ

// runMemoryCollection enumerates processes and dumps each one's committed,
// private, executable/RWX memory regions. It performs NO interpretation — that
// is the lab analyzer's job. See process_memory_inspection.go for the design.
func runMemoryCollection(ctx *Context, result *Result) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("process enumeration (CreateToolhelp32Snapshot): %v", err))
		return
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("process enumeration (Process32First): %v", err))
		return
	}

	// Two index files. processes.csv = one row per process; regions.csv = one
	// row per selected region. Both are primary artifacts (the analyst's index
	// into the raw blobs under dumps/).
	procFile, procW, err := newCSV(ctx.OutputDir, "processes.csv",
		[]string{"pid", "name", "open_result", "regions_total", "regions_selected", "regions_dumped", "bytes_dumped"})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("create processes.csv: %v", err))
		return
	}
	defer procFile.Close()

	regFile, regW, err := newCSV(ctx.OutputDir, "regions.csv",
		[]string{"pid", "name", "base_addr", "region_size", "state", "protect", "type", "dumped", "bytes", "blob_path", "note"})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("create regions.csv: %v", err))
		return
	}
	defer regFile.Close()

	self := windows.GetCurrentProcessId()

	var (
		procCount     int
		openedCount   int
		deniedCount   int
		dumpedRegions int
		dumpedBytes   int64
		readErrors    int
		truncated     int
	)

	for {
		if ctx.Ctx.Err() != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("collection interrupted after %d process(es): %v", procCount, ctx.Ctx.Err()))
			break
		}

		pid := pe.ProcessID
		name := windows.UTF16ToString(pe.ExeFile[:])

		switch {
		case pid == 0 || pid == self:
			// System Idle process and our own process: nothing useful to read.
			_ = procW.Write([]string{u32(pid), name, "skipped", "0", "0", "0", "0"})
		default:
			procCount++
			h, oerr := windows.OpenProcess(processAccess, false, pid)
			if oerr != nil {
				// Expected for PPL/protected/system processes and under EDR.
				deniedCount++
				_ = procW.Write([]string{u32(pid), name, "denied: " + oerr.Error(), "0", "0", "0", "0"})
			} else {
				openedCount++
				total, selected, dumped, bytes, rerr, trunc := dumpProcessRegions(ctx, h, pid, name, regW)
				windows.CloseHandle(h)

				dumpedRegions += dumped
				dumpedBytes += bytes
				readErrors += rerr
				truncated += trunc

				_ = procW.Write([]string{
					u32(pid), name, "opened",
					strconv.Itoa(total), strconv.Itoa(selected), strconv.Itoa(dumped),
					strconv.FormatInt(bytes, 10),
				})
			}
		}

		// Process32Next returns ERROR_NO_MORE_FILES at the end of the snapshot.
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}

	procW.Flush()
	regW.Flush()

	// Register the two index CSVs as primary artifacts.
	for _, fn := range []string{"processes.csv", "regions.csv"} {
		if a, derr := describeArtifact(filepath.Join(ctx.OutputDir, fn)); derr == nil {
			result.Artifacts = append(result.Artifacts, a)
		} else {
			result.AddWarning(fn, fmt.Sprintf("hash failed: %v", derr))
		}
	}

	// Raw region blobs under dumps/ are bulk files (hashed by the manifest
	// walker, which walks the module directory recursively).
	result.BulkFiles = dumpedRegions

	if openedCount == 0 {
		// Opening nothing means the run is genuinely degraded — not elevated,
		// or EDR stripped every handle. That is a warning (→ partial status).
		result.AddWarning("process_memory_inspection",
			fmt.Sprintf("could not open any of %d process(es) for memory read — process likely not elevated, or reads blocked by EDR", procCount))
		return
	}

	result.AddInfo("process_memory_inspection",
		fmt.Sprintf("inspected %d process(es): %d opened, %d denied; dumped %d exec/RWX-private region(s), %d byte(s) to dumps/ (%d read error(s), %d region(s) truncated at %d MiB cap)",
			procCount, openedCount, deniedCount, dumpedRegions, dumpedBytes, readErrors, truncated, maxRegionBytes/(1024*1024)))
	result.AddInfo("process_memory_inspection",
		"reads process memory via OpenProcess/ReadProcessMemory and is EDR-visible; denied processes (PPL/protected/system) are expected, not errors. All interpretation (strings, PE-carve, RWX triage) happens lab-side via safe --analyze.")
}

// dumpProcessRegions walks one opened process's address space and dumps every
// selected region. It returns counts for the per-process index row.
func dumpProcessRegions(ctx *Context, h windows.Handle, pid uint32, name string, regW *csv.Writer) (total, selected, dumped int, bytes int64, readErrs, trunc int) {
	dumpDir := filepath.Join(ctx.OutputDir, "dumps", fmt.Sprintf("%d_%s", pid, sanitizeName(name)))
	dirMade := false

	var addr uintptr
	for {
		if ctx.Ctx.Err() != nil {
			return
		}

		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			// End of the address space (ERROR_INVALID_PARAMETER) or query end.
			break
		}
		if mbi.RegionSize == 0 {
			break // no forward progress possible
		}
		total++

		if regionSelected(&mbi) {
			selected++
			n, wasTrunc, blobRel, derr := dumpRegion(dumpDir, &dirMade, h, &mbi, pid, name)
			if derr != nil {
				readErrs++
				_ = regW.Write(regionRow(pid, name, &mbi, false, 0, "", derr.Error()))
			} else {
				dumped++
				bytes += n
				note := ""
				if wasTrunc {
					trunc++
					note = "truncated to cap"
				}
				_ = regW.Write(regionRow(pid, name, &mbi, true, n, blobRel, note))
			}
		}

		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break // guard against overflow / non-advancing walk
		}
		addr = next
	}
	return
}

// dumpRegion reads one region and writes its bytes to a blob file. The dump
// directory is created lazily on first successful read so processes with no
// selected regions leave no empty directory behind.
func dumpRegion(dumpDir string, dirMade *bool, h windows.Handle, mbi *windows.MemoryBasicInformation, pid uint32, name string) (n int64, truncated bool, blobRel string, err error) {
	size := mbi.RegionSize
	if size > maxRegionBytes {
		size = maxRegionBytes
		truncated = true
	}

	buf := make([]byte, int(size))
	var nRead uintptr
	if rerr := windows.ReadProcessMemory(h, mbi.BaseAddress, &buf[0], size, &nRead); rerr != nil {
		return 0, false, "", fmt.Errorf("read error: %v", rerr)
	}

	if !*dirMade {
		if merr := os.MkdirAll(dumpDir, 0o755); merr != nil {
			return 0, false, "", fmt.Errorf("mkdir error: %v", merr)
		}
		*dirMade = true
	}

	blob := fmt.Sprintf("%x_%d.bin", mbi.BaseAddress, nRead)
	if werr := os.WriteFile(filepath.Join(dumpDir, blob), buf[:nRead], 0o644); werr != nil {
		return 0, false, "", fmt.Errorf("write error: %v", werr)
	}

	rel := filepath.ToSlash(filepath.Join("dumps", fmt.Sprintf("%d_%s", pid, sanitizeName(name)), blob))
	return int64(nRead), truncated, rel, nil
}

// regionSelected applies the collection scope filter: committed, private
// (non-image/non-mapped), readable, executable-or-RWX regions. This is a
// protection-flag filter, not content analysis.
func regionSelected(mbi *windows.MemoryBasicInformation) bool {
	if mbi.State != windows.MEM_COMMIT {
		return false
	}
	if mbi.Type != memPrivate {
		return false // exclude image-backed (on disk) and mapped regions
	}
	if mbi.Protect&windows.PAGE_GUARD != 0 {
		return false // guard pages fault on read
	}
	const execAny = windows.PAGE_EXECUTE | windows.PAGE_EXECUTE_READ |
		windows.PAGE_EXECUTE_READWRITE | windows.PAGE_EXECUTE_WRITECOPY
	return mbi.Protect&execAny != 0
}

// regionRow builds a regions.csv row.
func regionRow(pid uint32, name string, mbi *windows.MemoryBasicInformation, dumped bool, n int64, blob, note string) []string {
	return []string{
		u32(pid), name,
		fmt.Sprintf("0x%x", mbi.BaseAddress),
		strconv.FormatUint(uint64(mbi.RegionSize), 10),
		stateString(mbi.State),
		protString(mbi.Protect),
		typeString(mbi.Type),
		strconv.FormatBool(dumped),
		strconv.FormatInt(n, 10),
		blob, note,
	}
}

// newCSV creates a CSV file in dir, writes the header, and returns the open
// file (for the caller to Close) and a writer (for the caller to Flush).
func newCSV(dir, name string, header []string) (*os.File, *csv.Writer, error) {
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return nil, nil, err
	}
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, w, nil
}

// sanitizeName makes a process name safe for use as a directory component.
func sanitizeName(s string) string {
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

func u32(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func protString(p uint32) string {
	base := map[uint32]string{
		windows.PAGE_NOACCESS:          "NOACCESS",
		windows.PAGE_READONLY:          "R",
		windows.PAGE_READWRITE:         "RW",
		windows.PAGE_WRITECOPY:         "WC",
		windows.PAGE_EXECUTE:           "X",
		windows.PAGE_EXECUTE_READ:      "RX",
		windows.PAGE_EXECUTE_READWRITE: "RWX",
		windows.PAGE_EXECUTE_WRITECOPY: "WCX",
	}
	s, ok := base[p&0xFF]
	if !ok {
		s = fmt.Sprintf("0x%x", p&0xFF)
	}
	if p&windows.PAGE_GUARD != 0 {
		s += "+GUARD"
	}
	if p&windows.PAGE_NOCACHE != 0 {
		s += "+NOCACHE"
	}
	return s
}

func typeString(t uint32) string {
	switch t {
	case memImage:
		return "IMAGE"
	case memMapped:
		return "MAPPED"
	case memPrivate:
		return "PRIVATE"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

func stateString(s uint32) string {
	switch s {
	case windows.MEM_COMMIT:
		return "COMMIT"
	case windows.MEM_RESERVE:
		return "RESERVE"
	case memFree:
		return "FREE"
	default:
		return fmt.Sprintf("0x%x", s)
	}
}
