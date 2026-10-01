package csvutil

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadCSVHelper is a utility to iterate over a CSV file with named columns.
//
// A row with fewer fields than the header is skipped (it can't be indexed by
// column safely). Such rows were previously dropped silently — a real gap for a
// detection pipeline, where a subtly malformed row from an upstream parser is a
// silently missed artifact or behavioral hit. The count of skipped short rows is
// now reported once per file to stderr so the loss is visible, while the
// signature is unchanged so the ~30 call sites need no update.
func ReadCSVHelper(path string, callback func(header []string, row []string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // Allow variable number of fields

	header, err := r.Read()
	if err != nil {
		return err
	}

	shortRows := 0
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(row) < len(header) {
			shortRows++
			continue
		}
		if err := callback(header, row); err != nil {
			return err
		}
	}
	if shortRows > 0 {
		fmt.Fprintf(os.Stderr, "csvutil: %s: skipped %d row(s) with fewer columns than the %d-column header\n",
			path, shortRows, len(header))
	}
	return nil
}

// CsvSafe neutralizes spreadsheet formula injection in a CSV field. A cell whose
// first character is one of = + - @ (or a leading tab/CR) is interpreted as a
// formula by Excel/LibreOffice, so a value harvested from a compromised host —
// an attacker-named file, a registry value, a command line like
// "=cmd|'/c calc'!A1" — could execute when an analyst opens the CSV. Prefixing
// such a value with a single quote forces the spreadsheet to treat it as literal
// text without changing what a plain text/grep reader sees. Apply only to
// free-text columns, never to numeric or timestamp columns. A value that already
// starts with a quote is left as-is (the danger set does not include the quote),
// so re-applying this is idempotent and it never strips a legitimate leading
// apostrophe from evidence data. This is the single shared implementation used
// across the analyzer, timeline, and behavior packages.
func CsvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// GetColIndex finds the index of a column in the header slice, ignoring case.
func GetColIndex(header []string, colName string) int {
	for i, h := range header {
		if strings.EqualFold(h, colName) {
			return i
		}
	}
	return -1
}

// SafeIndex safely retrieves an element from a string slice.
func SafeIndex(row []string, idx int) string {
	if idx >= 0 && idx < len(row) {
		return row[idx]
	}
	return ""
}
