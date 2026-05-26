package manifest

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VerifyResult is the outcome of verifying a case folder.
type VerifyResult struct {
	CaseDir      string
	FilesChecked int
	Mismatches   []string
	Missing      []string
	OK           bool
}

// Verify walks the manifest.sha256 in caseDir and checks every file
// against its recorded hash. Returns a VerifyResult describing what passed
// and what failed.
func Verify(caseDir string) (*VerifyResult, error) {
	sha256Path := filepath.Join(caseDir, "manifest.sha256")
	f, err := os.Open(sha256Path)
	if err != nil {
		return nil, fmt.Errorf("open manifest.sha256: %w", err)
	}
	defer f.Close()

	result := &VerifyResult{
		CaseDir: caseDir,
		OK:      true,
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Format: "<hash>  <relative_path>"
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			result.Mismatches = append(result.Mismatches,
				fmt.Sprintf("malformed line: %q", line))
			result.OK = false
			continue
		}
		expectedHash := parts[0]
		relPath := parts[1]
		absPath := filepath.Join(caseDir, relPath)

		actualHash, err := sha256File(absPath)
		if err != nil {
			if os.IsNotExist(err) {
				result.Missing = append(result.Missing, relPath)
			} else {
				result.Mismatches = append(result.Mismatches,
					fmt.Sprintf("%s: %v", relPath, err))
			}
			result.OK = false
			continue
		}

		if actualHash != expectedHash {
			result.Mismatches = append(result.Mismatches,
				fmt.Sprintf("%s: hash mismatch (expected %s, got %s)",
					relPath, expectedHash, actualHash))
			result.OK = false
		}
		result.FilesChecked++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read manifest.sha256: %w", err)
	}

	return result, nil
}
