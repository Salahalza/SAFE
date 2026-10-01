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
	// Extra lists regular files present on disk under the case folder that no
	// manifest accounts for. For a chain-of-custody tool, files ADDED to
	// evidence matter as much as files modified or removed: a plain allowlist
	// check would silently pass planted data. Reconciliation closes that gap.
	Extra []string
	OK    bool
}

// Verify checks the integrity of a completed case folder. It does three things:
//
//  1. verifies every file listed in <caseDir>/manifest.sha256 (collection side);
//  2. verifies every file listed in <caseDir>/lab_report/manifest.sha256 when
//     analysis has run (the analyzer writes a manifest but nothing previously
//     verified it); and
//  3. reconciles against the filesystem, flagging any regular file on disk that
//     no manifest covers (added/planted evidence).
//
// Any modification, removal, or addition of a file under the case folder is
// detected. The only files legitimately left uncovered are the manifests
// themselves (which cannot hash themselves) and the report server's derived,
// regenerable artifacts (the timeline.db cache and its sidecars, and the tags
// file), which are not collected evidence.
func Verify(caseDir string) (*VerifyResult, error) {
	result := &VerifyResult{CaseDir: caseDir, OK: true}

	// covered holds the cleaned absolute path of every file a manifest accounts
	// for, so the reconciliation walk in step 3 can tell evidence from planted
	// files.
	covered := make(map[string]bool)

	// 1. Case manifest — module artifacts, module.json files, top-level files.
	//    Entries are relative to caseDir.
	caseManifest := filepath.Join(caseDir, "manifest.sha256")
	if err := verifyManifestFile(caseManifest, caseDir, result, covered); err != nil {
		return nil, err
	}

	// 2. Lab-report manifest, if analysis has run. Entries are relative to the
	//    lab_report dir. Without this, analyzer output (the CSVs, the extracted
	//    strings, analyzer_result.json — the analyst-facing findings) has a hash
	//    manifest written but no verification path at all.
	labDir := filepath.Join(caseDir, "lab_report")
	labManifest := filepath.Join(labDir, "manifest.sha256")
	if _, err := os.Stat(labManifest); err == nil {
		if err := verifyManifestFile(labManifest, labDir, result, covered); err != nil {
			return nil, err
		}
	}

	// The manifests themselves are legitimately not self-hashed; mark them
	// covered so the reconciliation does not report them as planted files.
	for _, self := range []string{
		filepath.Join(caseDir, "manifest.json"),
		filepath.Join(caseDir, "manifest.sha256"),
		filepath.Join(labDir, "manifest.sha256"),
	} {
		markCovered(covered, self)
	}

	// Derived, regenerable report artifacts that the report server and the
	// analyst's own tagging create AFTER the manifests are written, and that are
	// never entered into any manifest: the rebuildable SQLite timeline cache
	// (with its WAL/SHM/journal sidecars) and the tags file. These are not
	// collected evidence — the timeline cache is derived from timeline.csv and
	// tags are the analyst's annotations. Without excluding them, `-verify`
	// flags any case that has merely been opened in the report (which builds
	// timeline.db) or had a finding tagged as "possible tampering" — a false
	// positive on ordinary use that trains analysts to ignore the tamper signal.
	for _, derived := range []string{
		filepath.Join(labDir, "timeline.db"),
		filepath.Join(labDir, "timeline.db-wal"),
		filepath.Join(labDir, "timeline.db-shm"),
		filepath.Join(labDir, "timeline.db-journal"),
		filepath.Join(caseDir, "tags.json"),
	} {
		markCovered(covered, derived)
	}

	// 3. Reconciliation walk — any regular file not covered is extra.
	if err := findExtraFiles(caseDir, covered, result); err != nil {
		return nil, err
	}

	return result, nil
}

// verifyManifestFile reads a "<hash>  <relpath>" manifest at manifestPath whose
// entries are relative to root, checks each referenced file's hash, and records
// each referenced file's absolute path in covered.
func verifyManifestFile(manifestPath, root string, result *VerifyResult, covered map[string]bool) error {
	f, err := os.Open(manifestPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", filepath.Base(manifestPath), err)
	}
	defer f.Close()

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
		absPath := filepath.Join(root, relPath)
		markCovered(covered, absPath)

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
		return fmt.Errorf("read %s: %w", filepath.Base(manifestPath), err)
	}
	return nil
}

// findExtraFiles walks caseDir and appends any regular file whose absolute path
// is not in covered to result.Extra, failing verification. This turns the
// manifest from an allowlist into a full reconciliation: a file dropped into a
// module dir or the case root after collection is caught instead of silently
// accepted.
func findExtraFiles(caseDir string, covered map[string]bool, result *VerifyResult) error {
	return filepath.Walk(caseDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if covered[filepath.Clean(abs)] {
			return nil
		}
		rel, err := filepath.Rel(caseDir, path)
		if err != nil {
			rel = path
		}
		result.Extra = append(result.Extra, filepath.ToSlash(rel))
		result.OK = false
		return nil
	})
}

// markCovered records the cleaned absolute form of path in covered. Errors
// resolving the absolute path are ignored — a path that cannot be made absolute
// simply will not match the reconciliation walk, which fails safe (an
// unmatched file is flagged, never silently passed).
func markCovered(covered map[string]bool, path string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return
	}
	covered[filepath.Clean(abs)] = true
}
