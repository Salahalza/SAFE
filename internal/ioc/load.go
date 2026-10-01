package ioc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// STIXBundle is a minimal struct for deserializing a STIX 2.1 bundle.
// Only fields needed for indicator matching are parsed.
type STIXBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Objects []STIXObject `json:"objects"`
}

// STIXObject is a minimal representation of a STIX 2.1 domain object.
type STIXObject struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
}

// LoadPacks reads all STIX 2.1 bundles from dir and returns all indicator
// objects found. BUG 7 fix: if dir does not exist the function returns an
// empty slice (not an error) and prints a diagnostic, keeping analysis usable
// even when no intelligence packs have been generated yet.
func LoadPacks(dir string) ([]STIXObject, error) {
	// BUG 7: check directory existence before globbing.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Info: IOC pack directory %q not found — no intelligence loaded.\n", dir)
		fmt.Fprintf(os.Stderr, "      Run `safe-analyze --extract-iocs <file>` to create packs.\n")
		return nil, nil
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("glob iocs: %w", err)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "Info: No STIX packs found in %q.\n", dir)
		return nil, nil
	}

	var allIndicators []STIXObject

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to read IOC pack %s: %v\n", file, err)
			continue
		}

		var bundle STIXBundle
		if err := json.Unmarshal(data, &bundle); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse STIX bundle %s: %v\n", file, err)
			continue
		}

		for _, obj := range bundle.Objects {
			if obj.Type == "indicator" && obj.Pattern != "" {
				allIndicators = append(allIndicators, obj)
			}
		}
	}

	return allIndicators, nil
}
