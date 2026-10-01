package analyzer

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// USNParser parses the raw UsnJrnl_J file extracted during collection.
type USNParser struct{}

func (p *USNParser) Name() string { return "usnjrnl" }

func (p *USNParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	// The ntfs_metadata module writes the USN journal to
	// modules/NN_ntfs_metadata/UsnJrnl_J; resolve it by glob like the other parsers.
	usnPath := firstGlob(caseDir, filepath.Join("modules", "*_ntfs_metadata", "UsnJrnl_J"))
	if usnPath == "" {
		return nil, nil, nil
	}

	outPath := filepath.Join(labReportDir, "usn.csv")
	out, err := os.Create(outPath)
	if err != nil {
		return nil, nil, []error{err}
	}
	defer out.Close()

	w := csv.NewWriter(out)
	header := []string{"timestamp", "filename", "reason"}
	_ = w.Write(header)

	f, err := os.Open(usnPath)
	if err != nil {
		return nil, nil, []error{err}
	}
	defer f.Close()

	stat, _ := f.Stat()
	fileSize := stat.Size()
	stats := ParseStats{"records_processed": 0}
	var parseErrs []error

	// Stream the journal in large sequential blocks rather than re-reading a
	// fresh 64 KiB window at every record. The previous code issued a full
	// ReadAt(64 KiB) each iteration while the cursor advanced by only one record
	// (~60-100 bytes), re-reading the same bytes hundreds of times per record —
	// crippling on a real multi-hundred-MB/GB UsnJrnl_J. A single sliding window,
	// refilled only when the next record would cross its end, reads each byte ~once.
	const bufSize = 1 << 20 // 1 MiB (comfortably larger than the max sane record)
	buf := make([]byte, bufSize)
	var bufBase int64 = -1
	bufLen := 0

	// window returns a slice of exactly `need` bytes of the journal starting at
	// file offset off, refilling the buffer when the request falls outside it.
	// Returns nil at end-of-file / short tail. A genuine read error is surfaced.
	window := func(off int64, need int) []byte {
		if bufBase < 0 || off < bufBase || off+int64(need) > bufBase+int64(bufLen) {
			n, err := f.ReadAt(buf, off)
			if err != nil && err != io.EOF {
				parseErrs = append(parseErrs, fmt.Errorf("read USN at offset %d: %w", off, err))
			}
			bufBase = off
			bufLen = n
			if report != nil {
				report(int(off), int(fileSize))
			}
		}
		rel := int(off - bufBase)
		if rel < 0 || rel+need > bufLen {
			return nil
		}
		return buf[rel : rel+need]
	}

	var offset int64 = 0
	for {
		head := window(offset, 60)
		if head == nil {
			break // end of journal (or short tail)
		}

		// USN journals are sparse — long zero runs at the start. Skip a cluster.
		if head[0] == 0 && head[1] == 0 && head[2] == 0 && head[3] == 0 {
			offset += 4096
			continue
		}

		recordLen := binary.LittleEndian.Uint32(head[0:4])
		major := binary.LittleEndian.Uint16(head[4:6])

		// Basic sanity check for a USN v2 record.
		if recordLen >= 60 && recordLen <= 65536 && major == 2 {
			rec := window(offset, int(recordLen))
			if rec == nil {
				break // truncated final record
			}
			timestamp := binary.LittleEndian.Uint64(rec[32:40])
			reason := binary.LittleEndian.Uint32(rec[40:44])
			nameLen := binary.LittleEndian.Uint16(rec[56:58])
			nameOff := binary.LittleEndian.Uint16(rec[58:60])

			if int(nameOff)+int(nameLen) <= int(recordLen) {
				nameBytes := rec[nameOff : int(nameOff)+int(nameLen)]
				filename := decodeUTF16(nameBytes)

				reasonStr := formatReason(reason)
				if reasonStr != "" {
					ts := formatTime(filetimeToTime(timestamp))
					_ = w.Write([]string{ts, csvSafe(filename), reasonStr})
					stats["records_processed"]++
				}
			}
			offset += int64(recordLen)
		} else {
			offset += 8 // resync
		}
	}

	w.Flush()
	return []string{outPath}, stats, parseErrs
}

// usnReasonFlags is the full set of USN_REASON_* bits, low bit first for a stable
// decode order. The parser previously recognized only five of these, so a record
// whose reason had none of them — a lone DATA_OVERWRITE (the classic
// ransomware/tampering signal), a SECURITY_CHANGE, a REPARSE_POINT_CHANGE, or a
// CLOSE-only record — was dropped from usn.csv entirely, uncounted and with no
// trace. Decoding every defined reason keeps the journal's change history intact.
var usnReasonFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "DATA_OVERWRITE"},
	{0x00000002, "DATA_EXTEND"},
	{0x00000004, "DATA_TRUNCATION"},
	{0x00000010, "NAMED_DATA_OVERWRITE"},
	{0x00000020, "NAMED_DATA_EXTEND"},
	{0x00000040, "NAMED_DATA_TRUNCATION"},
	{0x00000100, "FILE_CREATE"},
	{0x00000200, "FILE_DELETE"},
	{0x00000400, "EA_CHANGE"},
	{0x00000800, "SECURITY_CHANGE"},
	{0x00001000, "RENAME_OLD_NAME"},
	{0x00002000, "RENAME_NEW_NAME"},
	{0x00004000, "INDEXABLE_CHANGE"},
	{0x00008000, "BASIC_INFO_CHANGE"},
	{0x00010000, "HARD_LINK_CHANGE"},
	{0x00020000, "COMPRESSION_CHANGE"},
	{0x00040000, "ENCRYPTION_CHANGE"},
	{0x00080000, "OBJECT_ID_CHANGE"},
	{0x00100000, "REPARSE_POINT_CHANGE"},
	{0x00200000, "STREAM_CHANGE"},
	{0x00400000, "TRANSACTED_CHANGE"},
	{0x00800000, "INTEGRITY_CHANGE"},
	{0x80000000, "CLOSE"},
}

func formatReason(reason uint32) string {
	if reason == 0 {
		return ""
	}
	var reasons []string
	var known uint32
	for _, f := range usnReasonFlags {
		if reason&f.bit != 0 {
			reasons = append(reasons, f.name)
			known |= f.bit
		}
	}
	// Preserve any bits not in the known set rather than silently discarding them.
	if rem := reason &^ known; rem != 0 {
		reasons = append(reasons, fmt.Sprintf("UNKNOWN(0x%X)", rem))
	}
	return strings.Join(reasons, "|")
}
