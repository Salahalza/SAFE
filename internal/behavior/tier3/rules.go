package tier3

import (
	"fmt"
	"github.com/Salahalza/SAFE/internal/analyzer/timeline"
	"github.com/Salahalza/SAFE/internal/behavior"
	"strings"
	"time"
)

// Rule defines the interface for a Tier 3 cross-artifact correlation rule.
type Rule interface {
	ID() string
	Name() string
	MITRE() string
	Severity() string
	// Process evaluates a single chronological event and returns any hits that trigger.
	Process(event timeline.Event) []behavior.Hit
	// Flush is called at the end of the timeline to yield any remaining hits.
	Flush() []behavior.Hit
}

// parseTime is a helper to convert a timeline event Date/Time into a time.Time
func parseTime(date, tStr string) time.Time {
	t, _ := time.Parse("2006-01-02 15:04:05.000000", date+" "+tStr)
	return t
}

// --- T3-01: ExecutionToNetwork (DISABLED — no data source) ---
//
// This rule and T3-02 correlate execution with network *connections*, but SAFE
// collects no network-connection events into the timeline, so neither can fire.
// They are not registered in engine.go (see the note there) and are retained only
// as ready-to-enable detections for if a network-event source is ever added.

type ExecState struct {
	Event timeline.Event
	Time  time.Time
}

type ExecutionToNetworkRule struct {
	recentExecutions []ExecState
	timeWindow       time.Duration
}

func NewExecutionToNetworkRule() *ExecutionToNetworkRule {
	return &ExecutionToNetworkRule{
		timeWindow: 2 * time.Minute,
	}
}

func (r *ExecutionToNetworkRule) ID() string       { return "T3-01" }
func (r *ExecutionToNetworkRule) Name() string     { return "Suspicious Execution Followed by Network Connection" }
func (r *ExecutionToNetworkRule) MITRE() string    { return "T1071" }
func (r *ExecutionToNetworkRule) Severity() string { return behavior.SeverityHigh }

func (r *ExecutionToNetworkRule) Process(event timeline.Event) []behavior.Hit {
	var hits []behavior.Hit
	evTime := parseTime(event.Date, event.Time)
	if evTime.IsZero() {
		return hits
	}

	// Evict old state
	valid := r.recentExecutions[:0]
	for _, state := range r.recentExecutions {
		if evTime.Sub(state.Time) <= r.timeWindow {
			valid = append(valid, state)
		}
	}
	r.recentExecutions = valid

	// 1. Is this a suspicious execution?
	if event.Type == "Last Run" || event.Type == "Process Creation" {
		short := strings.ToLower(event.Short)
		if strings.Contains(short, "powershell.exe") || 
		   strings.Contains(short, "cmd.exe") || 
		   strings.Contains(short, "wscript.exe") ||
		   strings.Contains(short, "cscript.exe") ||
		   strings.Contains(short, "mshta.exe") {
			r.recentExecutions = append(r.recentExecutions, ExecState{
				Event: event,
				Time:  evTime,
			})
		}
	}

	// 2. Is this a network connection?
	if event.Type == "Network Connection" || strings.Contains(strings.ToLower(event.Short), "network connection") {
		// Found a network connection! Were there any recent suspicious executions?
		for _, exec := range r.recentExecutions {
			hits = append(hits, behavior.Hit{
				RuleID:         r.ID(),
				Severity:       r.Severity(),
				MITRE:          r.MITRE(),
				Title:          r.Name(),
				EvidenceSource: "timeline.csv",
				EvidenceDetail: fmt.Sprintf("Process %s executed at %s (Source: %s) followed by Network Connection at %s (Details: %s)",
					exec.Event.Short, exec.Event.Time, exec.Event.SourceType, event.Time, event.Desc),
			})
		}
		// Clear executions to prevent duplicate hits for the same execution
		r.recentExecutions = nil
	}

	return hits
}

func (r *ExecutionToNetworkRule) Flush() []behavior.Hit {
	return nil
}

// --- T3-02: NetworkToExecution (DISABLED — no data source; see T3-01) ---

type NetState struct {
	Event timeline.Event
	Time  time.Time
}

type NetworkToExecutionRule struct {
	recentConnections []NetState
	timeWindow        time.Duration
}

func NewNetworkToExecutionRule() *NetworkToExecutionRule {
	return &NetworkToExecutionRule{
		timeWindow: 2 * time.Minute,
	}
}

func (r *NetworkToExecutionRule) ID() string       { return "T3-02" }
func (r *NetworkToExecutionRule) Name() string     { return "Network Connection Followed by Suspicious Execution" }
func (r *NetworkToExecutionRule) MITRE() string    { return "T1105" }
func (r *NetworkToExecutionRule) Severity() string { return behavior.SeverityHigh }

func (r *NetworkToExecutionRule) Process(event timeline.Event) []behavior.Hit {
	var hits []behavior.Hit
	evTime := parseTime(event.Date, event.Time)
	if evTime.IsZero() {
		return hits
	}

	valid := r.recentConnections[:0]
	for _, state := range r.recentConnections {
		if evTime.Sub(state.Time) <= r.timeWindow {
			valid = append(valid, state)
		}
	}
	r.recentConnections = valid

	if event.Type == "Network Connection" || strings.Contains(strings.ToLower(event.Short), "network connection") {
		r.recentConnections = append(r.recentConnections, NetState{
			Event: event,
			Time:  evTime,
		})
	}

	if event.Type == "Last Run" || event.Type == "Process Creation" {
		short := strings.ToLower(event.Short)
		if strings.Contains(short, "powershell.exe") || 
		   strings.Contains(short, "cmd.exe") || 
		   strings.Contains(short, "certutil.exe") ||
		   strings.Contains(short, "bitsadmin.exe") {
			for _, conn := range r.recentConnections {
				hits = append(hits, behavior.Hit{
					RuleID:         r.ID(),
					Severity:       r.Severity(),
					MITRE:          r.MITRE(),
					Title:          r.Name(),
					EvidenceSource: "timeline.csv",
					EvidenceDetail: fmt.Sprintf("Network connection at %s (Details: %s) followed by process execution %s at %s (Source: %s)",
						conn.Event.Time, conn.Event.Desc, event.Short, event.Time, event.SourceType),
				})
			}
			r.recentConnections = nil
		}
	}

	return hits
}

func (r *NetworkToExecutionRule) Flush() []behavior.Hit {
	return nil
}

// --- T3-03: LateralMovementToExecution ---

type LateralState struct {
	Event timeline.Event
	Time  time.Time
}

type LateralMovementToExecutionRule struct {
	recentLateral []LateralState
	timeWindow    time.Duration
}

func NewLateralMovementToExecutionRule() *LateralMovementToExecutionRule {
	return &LateralMovementToExecutionRule{
		timeWindow: 2 * time.Minute,
	}
}

func (r *LateralMovementToExecutionRule) ID() string       { return "T3-03" }
func (r *LateralMovementToExecutionRule) Name() string     { return "Lateral Movement Followed by Execution" }
func (r *LateralMovementToExecutionRule) MITRE() string    { return "T1543.003" }
func (r *LateralMovementToExecutionRule) Severity() string { return behavior.SeverityHigh }

func (r *LateralMovementToExecutionRule) Process(event timeline.Event) []behavior.Hit {
	var hits []behavior.Hit
	evTime := parseTime(event.Date, event.Time)
	if evTime.IsZero() {
		return hits
	}

	valid := r.recentLateral[:0]
	for _, state := range r.recentLateral {
		if evTime.Sub(state.Time) <= r.timeWindow {
			valid = append(valid, state)
		}
	}
	r.recentLateral = valid

	// Capture a network (Type 3) logon — a 4624 with LogonType 3, the remote-
	// authentication half of the PsExec-style pattern. The timeline eventlog
	// adapter emits Type "EventID: 4624" and carries the event data JSON in Desc,
	// where LogonType is a bare integer.
	if event.Type == "EventID: 4624" && isLogonType3(event.Desc) {
		r.recentLateral = append(r.recentLateral, LateralState{
			Event: event,
			Time:  evTime,
		})
	}

	// Trigger on a SUSPICIOUS service creation shortly after — 7045 (System log)
	// or 4697 (Security log). A bare logon→service correlation is far too noisy to
	// be useful: on a domain controller, network (Type 3) logons and benign
	// driver/application service installs happen constantly, so requiring only a
	// service creation fires hundreds of times on a clean host and buries the real
	// signal. The service's own image must look like remote code execution (a
	// PsExec-style binary in a temp/user-writable/UNC location, or a script/LOLBin
	// interpreter) — a benign driver or Program Files service install does not
	// match. This fires once per suspicious service, citing the most recent logon.
	if event.Type == "EventID: 7045" || event.Type == "EventID: 4697" {
		if n := len(r.recentLateral); n > 0 && suspiciousServiceImage(event.Desc) {
			last := r.recentLateral[n-1]
			hits = append(hits, behavior.Hit{
				RuleID:         r.ID(),
				Severity:       r.Severity(),
				MITRE:          r.MITRE(),
				Title:          r.Name(),
				EvidenceSource: "timeline.csv",
				EvidenceDetail: fmt.Sprintf("Network logon (Type 3) at %s followed by suspicious service creation %q at %s",
					last.Event.Time, event.Short, event.Time),
			})
			r.recentLateral = nil
		}
	}

	return hits
}

// isLogonType3 reports whether a 4624 event's Desc (which embeds the event data
// JSON) records LogonType 3 (network logon). LogonType is a bare integer in the
// JSON, so it is matched exactly (followed by a comma or closing brace) to avoid
// "3" matching 13/30/etc.
func isLogonType3(desc string) bool {
	return strings.Contains(desc, `"LogonType":3,`) || strings.Contains(desc, `"LogonType":3}`)
}

// suspiciousServiceImage reports whether a service-creation event's binary path
// looks like remote code execution rather than a normal driver/application
// install. It reads the service image from the event data (7045 uses ImagePath,
// 4697 uses ServiceFileName) and flags temp/user-writable/UNC locations, script
// files, LOLBin interpreters, and known remote-exec service tools. A legitimate
// install (\SystemRoot\System32\drivers\…, C:\Program Files\…) does not match.
func suspiciousServiceImage(desc string) bool {
	path := jsonStringField(desc, "ImagePath")
	if path == "" {
		path = jsonStringField(desc, "ServiceFileName")
	}
	if path == "" {
		return false
	}
	p := strings.ToLower(path)
	// Strip a leading escaped quote so UNC detection sees the real first chars.
	p = strings.TrimPrefix(p, `\"`)
	if strings.HasPrefix(p, `\\`) {
		return true // UNC / admin-share service binary
	}
	// Locations/binaries that a legitimate service essentially never uses, but
	// remote-exec/PsExec-style service installs do. Deliberately excludes
	// \ProgramData\, \Users\, and \AppData\: legitimate software (Windows
	// Defender, per-user apps) installs services there, so including them
	// produced false positives on a clean host.
	markers := []string{
		`\temp\`, `\tmp\`, `\windows\temp\`, `\perflogs\`, `\$recycle`,
		`cmd.exe`, `cmd /c`, `cmd /k`, `powershell`, `pwsh`, `cscript`, `wscript`,
		`rundll32`, `regsvr32`, `mshta`, `.bat`, `.ps1`, `.vbs`, `.cmd`, `.js`,
		`psexesvc`, `paexec`, `csexec`,
	}
	for _, m := range markers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

// jsonStringField extracts the value of a "key":"value" pair from a JSON-ish
// string. It handles values wrapped in the escaped quotes the timeline uses,
// stopping at the next field boundary. Good enough for the flat event-data
// objects the eventlog adapter emits; not a general JSON parser.
func jsonStringField(s, key string) string {
	marker := `"` + key + `":"`
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	if end := strings.Index(rest, `","`); end >= 0 {
		return rest[:end]
	}
	if end := strings.Index(rest, `"}`); end >= 0 {
		return rest[:end]
	}
	return rest
}

func (r *LateralMovementToExecutionRule) Flush() []behavior.Hit {
	return nil
}

// --- T3-04: Suspicious Process Lineage ---

type ProcessState struct {
	Event timeline.Event
	Time  time.Time
}

type SuspiciousProcessLineageRule struct {
	recentOffice []ProcessState
	timeWindow   time.Duration
}

func NewSuspiciousProcessLineageRule() *SuspiciousProcessLineageRule {
	return &SuspiciousProcessLineageRule{
		timeWindow: 2 * time.Minute,
	}
}

func (r *SuspiciousProcessLineageRule) ID() string       { return "T3-04" }
func (r *SuspiciousProcessLineageRule) Name() string     { return "Suspicious Process Lineage (Office to Shell)" }
func (r *SuspiciousProcessLineageRule) MITRE() string    { return "T1059" }
func (r *SuspiciousProcessLineageRule) Severity() string { return behavior.SeverityHigh }

func (r *SuspiciousProcessLineageRule) Process(event timeline.Event) []behavior.Hit {
	var hits []behavior.Hit
	evTime := parseTime(event.Date, event.Time)
	if evTime.IsZero() {
		return hits
	}

	valid := r.recentOffice[:0]
	for _, state := range r.recentOffice {
		if evTime.Sub(state.Time) <= r.timeWindow {
			valid = append(valid, state)
		}
	}
	r.recentOffice = valid

	// Office/shell lineage keys off execution-artifact "Last Run" events
	// (Prefetch/UserAssist/BAM). The former "Process Creation" disjunct is removed
	// as dead: the timeline never emits that Type (process creation surfaces as
	// "EventID: 4688", whose Short does not carry the image name), so it only ever
	// matched nothing. Correlating 4688 would need event-data process-name parsing.
	if event.Type == "Last Run" {
		short := strings.ToLower(event.Short)
		if strings.Contains(short, "winword.exe") || strings.Contains(short, "excel.exe") || strings.Contains(short, "powerpnt.exe") {
			r.recentOffice = append(r.recentOffice, ProcessState{
				Event: event,
				Time:  evTime,
			})
		}

		// Look for Shells spawned recently after an Office App
		if strings.Contains(short, "cmd.exe") || strings.Contains(short, "powershell.exe") || strings.Contains(short, "wscript.exe") || strings.Contains(short, "cscript.exe") {
			for _, office := range r.recentOffice {
				hits = append(hits, behavior.Hit{
					RuleID:         r.ID(),
					Severity:       r.Severity(),
					MITRE:          r.MITRE(),
					Title:          r.Name(),
					EvidenceSource: "timeline.csv",
					EvidenceDetail: fmt.Sprintf("Office Application %s executed at %s followed closely by shell %s at %s", office.Event.Short, office.Event.Time, event.Short, event.Time),
				})
			}
			// Clear after hitting to prevent duplication
			if len(hits) > 0 {
				r.recentOffice = nil
			}
		}
	}

	return hits
}

func (r *SuspiciousProcessLineageRule) Flush() []behavior.Hit {
	return nil
}

