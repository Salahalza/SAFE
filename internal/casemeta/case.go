package casemeta

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Case holds the metadata an analyst provides when starting a collection.
// This metadata is the "case identity" — what links this collection to an
// incident, who ran it, what target it came from.
type Case struct {
	// CaseID is the analyst-supplied case identifier.
	// Format: free-form, but typically INC-YYYY-NNNN or similar.
	CaseID string `json:"case_id"`

	// Analyst is the name (or initials) of the team member running the collection.
	// This is an honor-system field — not authenticated.
	Analyst string `json:"analyst"`

	// TargetIdentifier is what the analyst calls this target.
	// Could be a hostname, asset tag, IP, or any free-form identifier.
	TargetIdentifier string `json:"target_identifier"`

	// TargetClass categorizes the target for profile selection later.
	// Values: "workstation", "server", "unknown".
	TargetClass string `json:"target_class"`

	// Notes is free-form analyst notes about this collection.
	Notes string `json:"notes,omitempty"`

	// ProfileName is which profile was selected (set by the engine, not analyst).
	ProfileName string `json:"profile_name"`

	// CreatedAt is when the case was initialized (UTC).
	CreatedAt time.Time `json:"created_at"`

	// SAHMVersion is the version of the tool that ran this collection.
	SAHMVersion string `json:"sahm_version"`
}

// Validate returns an error if required fields are missing or invalid.
func (c *Case) Validate() error {
	if strings.TrimSpace(c.CaseID) == "" {
		return fmt.Errorf("case ID is required")
	}
	if strings.TrimSpace(c.Analyst) == "" {
		return fmt.Errorf("analyst name is required")
	}
	if strings.TrimSpace(c.TargetIdentifier) == "" {
		return fmt.Errorf("target identifier is required")
	}
	if c.TargetClass != "workstation" && c.TargetClass != "server" && c.TargetClass != "unknown" {
		return fmt.Errorf("target class must be one of: workstation, server, unknown (got %q)", c.TargetClass)
	}
	return nil
}

// CaseDirName returns the directory name for this case.
// Format: CASE-<sanitized_case_id>_<timestamp>
// The timestamp is included to keep directory names unique even if the same
// case ID is collected from multiple targets.
func (c *Case) CaseDirName() string {
	sanitized := sanitizeForFilename(c.CaseID)
	timestamp := c.CreatedAt.UTC().Format("20060102-150405")
	return fmt.Sprintf("CASE-%s_%s", sanitized, timestamp)
}

// sanitizeForFilename replaces characters that aren't safe in filenames.
// Allows alphanumeric, hyphen, underscore. Everything else becomes underscore.
func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// WriteToCase writes the case metadata as case.json inside the case directory.
func (c *Case) WriteToCase(caseDir string) error {
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		return fmt.Errorf("create case dir: %w", err)
	}
	path := filepath.Join(caseDir, "case.json")
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal case: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write case.json: %w", err)
	}
	return nil
}
