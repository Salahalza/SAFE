package behavior

// Hit represents a single behavioral detection hit.
type Hit struct {
	RuleID         string
	Severity       string // HIGH, NOTABLE, INFO
	MITRE          string // e.g. T1059
	Title          string // Rule name/title
	EvidenceSource    string // Which CSV file triggered this
	EvidenceDetail    string // Description of what matched
	TimelineSearchKey string // Precise string to query in the timeline
}

// Rule defines the interface for a behavioral detection rule.
type Rule interface {
	ID() string
	Name() string
	MITRE() string
	Severity() string
	// Evaluate analyzes the given lab report directory and returns any hits.
	Evaluate(labReportDir string) []Hit
}

// Severity levels
const (
	SeverityHigh    = "HIGH"
	SeverityNotable = "NOTABLE"
	SeverityInfo    = "INFO"
)
