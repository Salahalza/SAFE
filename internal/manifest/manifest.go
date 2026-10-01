package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Salahalza/SAFE/internal/hashutil"
)

// SchemaVersion is the manifest schema version. Bump on breaking changes.
const SchemaVersion = "1.0.0"

// FileEntry describes a single file in the manifest.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ModuleManifest is the manifest written into each module's folder.
type ModuleManifest struct {
	SchemaVersion string      `json:"schema_version"`
	ModuleName    string      `json:"module_name"`
	GeneratedAt   time.Time   `json:"generated_at"`
	Artifacts     []FileEntry `json:"artifacts"`
}

// CaseManifest is the top-level manifest at the case root.
// It hashes every module.json and every top-level file.
type CaseManifest struct {
	SchemaVersion   string      `json:"schema_version"`
	CaseID          string      `json:"case_id"`
	GeneratedAt     time.Time   `json:"generated_at"`
	ModuleManifests []FileEntry `json:"module_manifests"`
	TopLevelFiles   []FileEntry `json:"top_level_files"`
}

// WriteModuleManifest creates module.json inside moduleDir, listing every
// artifact found in moduleDir (excluding module.json itself).
// Returns the FileEntry describing the module.json file just written.
func WriteModuleManifest(moduleDir, moduleName string) (FileEntry, error) {
	artifacts, err := scanDir(moduleDir, "module.json")
	if err != nil {
		return FileEntry{}, fmt.Errorf("scan module dir: %w", err)
	}

	mm := ModuleManifest{
		SchemaVersion: SchemaVersion,
		ModuleName:    moduleName,
		GeneratedAt:   time.Now().UTC(),
		Artifacts:     artifacts,
	}

	manifestPath := filepath.Join(moduleDir, "module.json")
	if err := writeJSON(manifestPath, mm); err != nil {
		return FileEntry{}, fmt.Errorf("write module manifest: %w", err)
	}

	entry, err := describe(manifestPath, moduleDir)
	if err != nil {
		return FileEntry{}, fmt.Errorf("hash module manifest: %w", err)
	}
	return entry, nil
}

// WriteCaseManifest creates manifest.json and manifest.sha256 at the case root.
// It hashes every module.json under modules/ and every file at the case root
// (excluding manifest.json and manifest.sha256 themselves).
func WriteCaseManifest(caseDir, caseID string) error {
	modulesDir := filepath.Join(caseDir, "modules")
	moduleManifests, err := findModuleManifests(modulesDir, caseDir)
	if err != nil {
		return fmt.Errorf("find module manifests: %w", err)
	}

	topLevel, err := scanTopLevel(caseDir)
	if err != nil {
		return fmt.Errorf("scan top level: %w", err)
	}

	cm := CaseManifest{
		SchemaVersion:   SchemaVersion,
		CaseID:          caseID,
		GeneratedAt:     time.Now().UTC(),
		ModuleManifests: moduleManifests,
		TopLevelFiles:   topLevel,
	}

	jsonPath := filepath.Join(caseDir, "manifest.json")
	if err := writeJSON(jsonPath, cm); err != nil {
		return fmt.Errorf("write case manifest: %w", err)
	}

	sha256Path := filepath.Join(caseDir, "manifest.sha256")
	if err := writeSHA256File(sha256Path, cm, caseDir); err != nil {
		return fmt.Errorf("write sha256 file: %w", err)
	}

	return nil
}

// scanDir returns FileEntries for every regular file in dir, excluding
// any files in the excludes list. Paths in returned entries are relative
// to dir.
func scanDir(dir string, excludes ...string) ([]FileEntry, error) {
	excludeSet := make(map[string]bool, len(excludes))
	for _, e := range excludes {
		excludeSet[e] = true
	}

	var entries []FileEntry
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if excludeSet[rel] {
			return nil
		}
		entry, err := describe(path, dir)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort for deterministic output.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	return entries, nil
}

// scanTopLevel returns FileEntries for files directly in caseDir,
// excluding manifest.json, manifest.sha256, and the modules/ subdir.
func scanTopLevel(caseDir string) ([]FileEntry, error) {
	entries, err := os.ReadDir(caseDir)
	if err != nil {
		return nil, err
	}

	excluded := map[string]bool{
		"manifest.json":   true,
		"manifest.sha256": true,
		"modules":         true,
	}

	var result []FileEntry
	for _, e := range entries {
		if e.IsDir() || excluded[e.Name()] {
			continue
		}
		path := filepath.Join(caseDir, e.Name())
		entry, err := describe(path, caseDir)
		if err != nil {
			return nil, err
		}
		result = append(result, entry)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Path < result[j].Path
	})
	return result, nil
}

// findModuleManifests scans modulesDir for every module.json file
// and returns FileEntries with paths relative to caseDir.
func findModuleManifests(modulesDir, caseDir string) ([]FileEntry, error) {
	var entries []FileEntry
	err := filepath.Walk(modulesDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Base(path) != "module.json" {
			return nil
		}
		entry, err := describe(path, caseDir)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	return entries, nil
}

// describe returns a FileEntry for path, with the Path field relative to relRoot.
func describe(path, relRoot string) (FileEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileEntry{}, err
	}
	hash, err := sha256File(path)
	if err != nil {
		return FileEntry{}, err
	}
	rel, err := filepath.Rel(relRoot, path)
	if err != nil {
		return FileEntry{}, err
	}
	// Always use forward slashes for cross-platform consistency in JSON.
	rel = filepath.ToSlash(rel)
	return FileEntry{
		Path:   rel,
		Size:   info.Size(),
		SHA256: hash,
	}, nil
}

// sha256File computes the SHA-256 hash of a file as a hex string, via the single
// shared hasher.
func sha256File(path string) (string, error) {
	return hashutil.SHA256File(path)
}

// writeJSON serializes v to path as indented JSON.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// writeSHA256File writes a plain-text sha256 manifest in the standard format
// that command-line `sha256sum -c` can verify.
// Format: "<hash>  <relative_path>" per line.
func writeSHA256File(path string, cm CaseManifest, caseDir string) error {
	// Collect every file referenced by the case manifest.
	var lines []string
	for _, f := range cm.TopLevelFiles {
		lines = append(lines, fmt.Sprintf("%s  %s", f.SHA256, f.Path))
	}
	for _, f := range cm.ModuleManifests {
		lines = append(lines, fmt.Sprintf("%s  %s", f.SHA256, f.Path))
		// Also include the artifacts the module manifest references.
		mm, err := readModuleManifest(filepath.Join(caseDir, f.Path))
		if err != nil {
			return err
		}
		// Module manifest's artifact paths are relative to the module dir.
		// Prefix with the module dir path for case-relative paths.
		moduleRel := filepath.ToSlash(filepath.Dir(f.Path))
		for _, a := range mm.Artifacts {
			lines = append(lines, fmt.Sprintf("%s  %s/%s", a.SHA256, moduleRel, a.Path))
		}
	}

	sort.Strings(lines)

	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// readModuleManifest reads and parses a module.json file.
func readModuleManifest(path string) (*ModuleManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var mm ModuleManifest
	if err := json.Unmarshal(data, &mm); err != nil {
		return nil, err
	}
	return &mm, nil
}
