package casemeta

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Case holds the metadata an analyst provides when starting a collection.
// This metadata is the "case identity" — what links this collection to an
// incident, who ran it, what target it came from.
type Case struct {
	// CaseID is the analyst-supplied case identifier.
	// Format: free-form, but typically INC-YYYY-NNNN or similar.
	// CaseID is the primary identifier and is always required. The case
	// folder name is built from CaseID, regardless of whether IRNumber or
	// CSINumber are also provided.
	CaseID string `json:"case_id"`

	// IRNumber is an optional cross-reference to an incident response ticket
	// in another system. When present, must match format IR-####-####
	// (four digits, hyphen, four digits — e.g., IR-2026-0418).
	IRNumber string `json:"ir_number,omitempty"`

	// CSINumber is an optional cross-reference to a CSI ticket in another
	// system. When present, must match format CSI-###### (six digits —
	// e.g., CSI-123456).
	CSINumber string `json:"csi_number,omitempty"`

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

	// ProfileVersion is the version of the selected profile. Recorded for
	// reproducibility — the same profile name can change which modules it runs
	// across releases, so the version pins exactly what was collected.
	ProfileVersion string `json:"profile_version,omitempty"`

	// CreatedAt is when the case was initialized (UTC).
	CreatedAt time.Time `json:"created_at"`

	// EndedAt is when collection finished (UTC). Zero until the run completes;
	// case.json is rewritten after the run to record it.
	EndedAt time.Time `json:"ended_at,omitempty"`

	// ShadowID is the Volume Shadow Copy used for this case, if any. Captured
	// for the audit trail (architectural principle #3) so the case-identity file
	// records which point-in-time snapshot the locked-file artifacts came from.
	// Empty when no module required VSS. Populated by the post-run rewrite.
	ShadowID string `json:"shadow_id,omitempty"`

	// SAFEVersion is the version of the tool that ran this collection.
	SAFEVersion string `json:"safe_version"`
}

// irNumberPattern matches IR-####-####, where # is a single digit.
var irNumberPattern = regexp.MustCompile(`^IR-\d{4}-\d{4}$`)

// csiNumberPattern matches CSI-######, where # is a single digit.
var csiNumberPattern = regexp.MustCompile(`^CSI-\d{6}$`)

// Validate returns an error if required fields are missing or invalid.
// IRNumber and CSINumber are optional; if provided, they must match their
// respective formats.
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

	// Optional fields: validate format only when present.
	if c.IRNumber != "" {
		trimmed := strings.TrimSpace(c.IRNumber)
		if !irNumberPattern.MatchString(trimmed) {
			return fmt.Errorf("IR number must match format IR-####-#### (e.g., IR-2026-0418); got %q", c.IRNumber)
		}
		c.IRNumber = trimmed
	}
	if c.CSINumber != "" {
		trimmed := strings.TrimSpace(c.CSINumber)
		if !csiNumberPattern.MatchString(trimmed) {
			return fmt.Errorf("CSI number must match format CSI-###### (e.g., CSI-123456); got %q", c.CSINumber)
		}
		c.CSINumber = trimmed
	}

	return nil
}

// PrimaryReference returns the most operationally relevant identifier for
// display purposes. IRNumber takes priority when present, then CSINumber,
// otherwise CaseID. The case folder name is always built from CaseID
// regardless of this priority.
func (c *Case) PrimaryReference() string {
	if c.IRNumber != "" {
		return c.IRNumber
	}
	if c.CSINumber != "" {
		return c.CSINumber
	}
	return c.CaseID
}

// CaseDirName returns the directory name for this case.
// Format: CASE-<sanitized_case_id>_<timestamp>
// The timestamp is included to keep directory names unique even if the same
// case ID is collected from multiple targets. IRNumber and CSINumber do not
// affect the folder name; they appear in case.json and reports only.
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
