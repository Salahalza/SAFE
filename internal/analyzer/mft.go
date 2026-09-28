package analyzer

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MFTParser parses the raw $MFT file extracted during collection.
// To keep performance high and avoid timeline bloat, it filters for interesting
// file extensions.
type MFTParser struct{}

func (p *MFTParser) Name() string { return "mft" }

func (p *MFTParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	// The ntfs_metadata module writes $MFT to modules/NN_ntfs_metadata/MFT, so
	// resolve it by glob like the other parsers rather than assuming the case root.
	mftPath := firstGlob(caseDir, filepath.Join("modules", "*_ntfs_metadata", "MFT"))
	if mftPath == "" {
		return nil, nil, nil // MFT not collected in this profile
	}

	outFullPath := filepath.Join(labReportDir, "mft_full.csv")
	outFull, err := os.Create(outFullPath)
	if err != nil {
		return nil, nil, []error{err}
	}
	defer outFull.Close()

	outTimelinePath := filepath.Join(labReportDir, "mft_timeline.csv")
	outTimeline, err := os.Create(outTimelinePath)
	if err != nil {
		return nil, nil, []error{err}
	}
	defer outTimeline.Close()

	wFull := csv.NewWriter(outFull)
	wTimeline := csv.NewWriter(outTimeline)

	header := []string{
		"mft_record", "filename", "creation_time", "modified_time", "mft_modified_time", "accessed_time",
	}
	_ = wFull.Write(header)
	_ = wTimeline.Write(header)

	f, err := os.Open(mftPath)
	if err != nil {
		return nil, nil, []error{err}
	}
	defer f.Close()

	stat, _ := f.Stat()
	fileSize := stat.Size()
	
	stats := ParseStats{"records_processed": 0, "records_exported": 0}
	var parseErrs []error

	// Read in 1024-byte MFT record chunks. io.ReadFull fills the whole record or
	// reports how the stream ended: a clean io.EOF (no more records) or an
	// io.ErrUnexpectedEOF (a trailing partial record) are both normal stops; any
	// other error is a genuine read failure that must be surfaced, not swallowed,
	// so the analyst knows records may be missing rather than reading a truncated
	// MFT as a complete one.
	buf := make([]byte, 1024)
	recordNum := 0

	for {
		if _, err := io.ReadFull(f, buf); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				parseErrs = append(parseErrs, fmt.Errorf("read MFT record %d: %w", recordNum, err))
			}
			break
		}

		if recordNum % 10000 == 0 && report != nil {
			report(int(int64(recordNum)*1024), int(fileSize))
		}

		stats["records_processed"]++

		// Check for 'FILE' magic signature
		if !bytes.HasPrefix(buf, []byte("FILE")) {
			recordNum++
			continue
		}

		// Very basic and unsafe attribute walk for Phase 11 demonstration
		attrOffset := binary.LittleEndian.Uint16(buf[20:22])
		
		var filename string
		var crTime, moTime, mftTime, acTime time.Time

		// Traverse attributes
		for attrOffset < 1024-8 {
			attrType := binary.LittleEndian.Uint32(buf[attrOffset : attrOffset+4])
			if attrType == 0xFFFFFFFF {
				break // End of attributes
			}

			attrLen := binary.LittleEndian.Uint32(buf[attrOffset+4 : attrOffset+8])
			if attrLen == 0 || uint32(attrOffset)+attrLen > 1024 {
				break // Corrupt
			}

			// STANDARD_INFORMATION (0x10). The line-99 guard only bounds
			// attrOffset+attrLen; the content-offset field itself lives at
			// attrOffset+20..22, so a short attrLen near the end of the buffer
			// would read out of bounds and panic (which, since parsers run as
			// unrecovered goroutines, would abort the whole analyze run). Guard
			// the 2-byte read explicitly.
			if attrType == 0x10 && uint32(attrOffset)+22 <= 1024 {
				contentOffset := uint32(binary.LittleEndian.Uint16(buf[attrOffset+20 : attrOffset+22]))
				if uint32(attrOffset)+contentOffset+32 <= 1024 {
					coff := uint32(attrOffset) + contentOffset
					cr := binary.LittleEndian.Uint64(buf[coff : coff+8])
					mo := binary.LittleEndian.Uint64(buf[coff+8 : coff+16])
					mft := binary.LittleEndian.Uint64(buf[coff+16 : coff+24])
					ac := binary.LittleEndian.Uint64(buf[coff+24 : coff+32])
					
					crTime = filetimeToTime(cr)
					moTime = filetimeToTime(mo)
					mftTime = filetimeToTime(mft)
					acTime = filetimeToTime(ac)
				}
			}

			// FILE_NAME (0x30). Same explicit bound as the 0x10 branch above.
			if attrType == 0x30 && uint32(attrOffset)+22 <= 1024 {
				contentOffset := uint32(binary.LittleEndian.Uint16(buf[attrOffset+20 : attrOffset+22]))
				if uint32(attrOffset)+contentOffset+66 <= 1024 {
					coff := uint32(attrOffset) + contentOffset
					nameLen := int(buf[coff+64])
					if coff+66+uint32(nameLen)*2 <= 1024 {
						nameBytes := buf[coff+66 : coff+66+uint32(nameLen)*2]
						filename = decodeUTF16(nameBytes)
					}
				}
			}

			attrOffset += uint16(attrLen)
		}

		if filename != "" {
			rowStr := []string{
				fmt.Sprintf("%d", recordNum),
				csvSafe(filename),
				formatTime(crTime),
				formatTime(moTime),
				formatTime(mftTime),
				formatTime(acTime),
			}
			
			// Always write to full dump
			_ = wFull.Write(rowStr)

			// Conditionally write to timeline stream
			if isInteresting(filename) {
				_ = wTimeline.Write(rowStr)
				stats["records_exported"]++
			}
		}

		recordNum++
	}

	wFull.Flush()
	wTimeline.Flush()
	return []string{outFullPath, outTimelinePath}, stats, parseErrs
}

func isInteresting(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".exe") || 
	       strings.HasSuffix(lower, ".dll") || 
	       strings.HasSuffix(lower, ".ps1") || 
	       strings.HasSuffix(lower, ".bat") ||
	       strings.HasSuffix(lower, ".vbs")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05.000000")
}

func decodeUTF16(b []byte) string {
	runes := make([]rune, len(b)/2)
	for i := 0; i < len(b)/2; i++ {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2 : i*2+2]))
	}
	return string(runes)
}
