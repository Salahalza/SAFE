package module

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// ContentCheck is an optional verification step for a command's output file.
// If the check fails, the artifact is downgraded from "success" to a warning,
// or in severe cases, removed from artifacts entirely.
type ContentCheck struct {
	// MinSize is the minimum acceptable file size in bytes.
	// 0 means no minimum. Default: 0.
	MinSize int64

	// MustContain are substrings (case-insensitive) that MUST appear
	// in the output for it to be considered valid.
	// Empty = no requirement.
	MustContain []string

	// MustNotContain are substrings (case-insensitive) that, if found,
	// indicate the command failed even though it exited cleanly.
	// Empty = no check.
	MustNotContain []string
}

// verifyContent runs the check against a file and returns a list of
// issues found. Empty slice means content passed all checks.
func (c *ContentCheck) verifyContent(path string) []string {
	var issues []string

	info, err := os.Stat(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot stat output: %v", err)}
	}

	if c.MinSize > 0 && info.Size() < c.MinSize {
		issues = append(issues,
			fmt.Sprintf("file size %d bytes is below minimum %d", info.Size(), c.MinSize))
	}

	if len(c.MustContain) == 0 && len(c.MustNotContain) == 0 {
		return issues
	}

	// Read full file for content scanning. Files we check this way are
	// expected to be small text output, not large binary blobs.
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot read output: %v", err)}
	}
	lower := bytes.ToLower(data)

	for _, needle := range c.MustContain {
		if !bytes.Contains(lower, []byte(strings.ToLower(needle))) {
			issues = append(issues,
				fmt.Sprintf("output missing expected content: %q", needle))
		}
	}

	for _, needle := range c.MustNotContain {
		if bytes.Contains(lower, []byte(strings.ToLower(needle))) {
			issues = append(issues,
				fmt.Sprintf("output contains error signature: %q", needle))
		}
	}

	return issues
}

// commonErrorSignatures are substrings that, when found in stdout-captured
// command output, indicate the command effectively failed even if it exited 0.
// Used as the default MustNotContain for stdout commands.
var commonErrorSignatures = []string{
	"access is denied",
	"a required privilege is not held",
	"the system was unable to find",
	"error:",
	"is not recognized as an internal",
	"the term '",
	"cannot find path",
	"unable to obtain",
	"the system cannot find the file",
	"the system cannot find the path",
}
