package analyzer

import (
	"encoding/xml"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScheduledTasksParser parses scheduled tasks XML data collected on the target system.
type ScheduledTasksParser struct{}

func (p *ScheduledTasksParser) Name() string { return "scheduled_tasks" }

// TasksXML represents the root element in the task scheduler XML backup.
type TasksXML struct {
	XMLName xml.Name  `xml:"Tasks"`
	Tasks   []TaskXML `xml:"Task"`
}

// TaskXML represents a single scheduled task.
type TaskXML struct {
	RegistrationInfo RegistrationInfoXML `xml:"RegistrationInfo"`
	Principals       PrincipalsXML       `xml:"Principals"`
	Settings         SettingsXML         `xml:"Settings"`
	Triggers         TriggersXML         `xml:"Triggers"`
	Actions          ActionsXML          `xml:"Actions"`
}

type RegistrationInfoXML struct {
	URI         string `xml:"URI"`
	Author      string `xml:"Author"`
	Description string `xml:"Description"`
	Version     string `xml:"Version"`
}

type PrincipalsXML struct {
	Principals []PrincipalXML `xml:"Principal"`
}

type PrincipalXML struct {
	ID        string `xml:"id,attr"`
	UserId    string `xml:"UserId"`
	GroupId   string `xml:"GroupId"`
	RunLevel  string `xml:"RunLevel"`
	LogonType string `xml:"LogonType"`
}

type SettingsXML struct {
	Enabled *bool `xml:"Enabled"`
}

type TriggersXML struct {
	BootTrigger               []struct{} `xml:"BootTrigger"`
	RegistrationTrigger       []struct{} `xml:"RegistrationTrigger"`
	IdleTrigger               []struct{} `xml:"IdleTrigger"`
	TimeTrigger               []struct{} `xml:"TimeTrigger"`
	EventTrigger              []struct{} `xml:"EventTrigger"`
	CalendarTrigger           []struct{} `xml:"CalendarTrigger"`
	LogonTrigger              []struct{} `xml:"LogonTrigger"`
	SessionStateChangeTrigger []struct{} `xml:"SessionStateChangeTrigger"`
	WnfStateChangeTrigger     []struct{} `xml:"WnfStateChangeTrigger"`
}

func (t TriggersXML) String() string {
	var list []string
	if len(t.BootTrigger) > 0 {
		list = append(list, "BootTrigger")
	}
	if len(t.RegistrationTrigger) > 0 {
		list = append(list, "RegistrationTrigger")
	}
	if len(t.IdleTrigger) > 0 {
		list = append(list, "IdleTrigger")
	}
	if len(t.TimeTrigger) > 0 {
		list = append(list, "TimeTrigger")
	}
	if len(t.EventTrigger) > 0 {
		list = append(list, "EventTrigger")
	}
	if len(t.CalendarTrigger) > 0 {
		list = append(list, "CalendarTrigger")
	}
	if len(t.LogonTrigger) > 0 {
		list = append(list, "LogonTrigger")
	}
	if len(t.SessionStateChangeTrigger) > 0 {
		list = append(list, "SessionStateChangeTrigger")
	}
	if len(t.WnfStateChangeTrigger) > 0 {
		list = append(list, "WnfStateChangeTrigger")
	}
	if len(list) == 0 {
		return "None"
	}
	return strings.Join(list, ", ")
}

type ActionsXML struct {
	Execs       []ExecXML       `xml:"Exec"`
	ComHandlers []ComHandlerXML `xml:"ComHandler"`
}

type ExecXML struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
}

type ComHandlerXML struct {
	ClassId string `xml:"ClassId"`
	Data    string `xml:"Data"`
}

var taskLolbins = []string{
	"powershell", "pwsh", "mshta", "rundll32", "regsvr32", "wscript", "cscript",
	"cmd.exe", "cmd ", "certutil", "bitsadmin", "msbuild", "installutil",
	"wmic", "schtasks", "curl", "msiexec",
}

// Parse extracts tasks from the collected XML, classifies them into tiers, and outputs a CSV file.
func (p *ScheduledTasksParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error

	persistDir := firstGlob(caseDir, filepath.Join("modules", "*_persistence_core"))
	if persistDir == "" {
		return nil, stats, nil
	}
	xmlFile := filepath.Join(persistDir, "scheduled_tasks_xml.txt")
	if _, err := os.Stat(xmlFile); os.IsNotExist(err) {
		return nil, stats, nil
	}

	data, err := os.ReadFile(xmlFile)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("read scheduled_tasks_xml.txt: %w", err)}
	}

	if report != nil {
		report(1, 3)
	}

	var root TasksXML
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, stats, []error{fmt.Errorf("unmarshal scheduled tasks xml: %w", err)}
	}

	// Fallback: schtasks /query can emit a bare <Task> element without the
	// <Tasks> wrapper when exporting a single task. If unmarshalling into the
	// multi-task root yielded no tasks, try parsing as a single TaskXML.
	if len(root.Tasks) == 0 {
		var single TaskXML
		if err := xml.Unmarshal(data, &single); err == nil && single.RegistrationInfo.URI != "" {
			root.Tasks = []TaskXML{single}
		}
	}

	if report != nil {
		report(2, 3)
	}

	outDir := filepath.Join(labReportDir, "scheduled_tasks")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, []error{fmt.Errorf("create output dir: %w", err)}
	}

	csvPath := filepath.Join(outDir, "tasks.csv")
	f, err := os.Create(csvPath)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("create tasks.csv: %w", err)}
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"tier", "task_name", "enabled", "triggers", "action_type",
		"command", "arguments", "com_class_id", "com_data",
		"user_id", "group_id", "run_level", "logon_type", "author", "description", "flags",
	}
	if err := w.Write(header); err != nil {
		return nil, stats, []error{fmt.Errorf("write csv header: %w", err)}
	}

	highCount := 0
	notableCount := 0
	lowCount := 0

	for _, t := range root.Tasks {
		enabled := true
		if t.Settings.Enabled != nil {
			enabled = *t.Settings.Enabled
		}

		// Principal
		var principal PrincipalXML
		if len(t.Principals.Principals) > 0 {
			principal = t.Principals.Principals[0]
		}

		// Triage
		tier, flags := triageTask(t.RegistrationInfo.URI, enabled, t.Actions.Execs, t.Actions.ComHandlers, principal)
		switch tier {
		case "HIGH":
			highCount++
		case "NOTABLE":
			notableCount++
		default:
			lowCount++
		}

		// Actions details
		actionType := "None"
		var cmds []string
		var args []string
		var classIds []string
		var comDataList []string

		for _, exec := range t.Actions.Execs {
			cmds = append(cmds, exec.Command)
			if exec.Arguments != "" {
				args = append(args, exec.Arguments)
			}
		}
		for _, com := range t.Actions.ComHandlers {
			classIds = append(classIds, com.ClassId)
			if com.Data != "" {
				comDataList = append(comDataList, com.Data)
			}
		}

		if len(t.Actions.Execs) > 0 && len(t.Actions.ComHandlers) > 0 {
			actionType = "Multiple"
		} else if len(t.Actions.Execs) > 0 {
			actionType = "Exec"
		} else if len(t.Actions.ComHandlers) > 0 {
			actionType = "ComHandler"
		}

		if err := w.Write([]string{
			tier,
			csvSafe(t.RegistrationInfo.URI),
			fmt.Sprintf("%t", enabled),
			t.Triggers.String(),
			actionType,
			csvSafe(strings.Join(cmds, " ; ")),
			csvSafe(strings.Join(args, " ; ")),
			csvSafe(strings.Join(classIds, " ; ")),
			csvSafe(strings.Join(comDataList, " ; ")),
			principal.UserId,
			principal.GroupId,
			principal.RunLevel,
			principal.LogonType,
			csvSafe(t.RegistrationInfo.Author),
			csvSafe(t.RegistrationInfo.Description),
			flags,
		}); err != nil {
			errs = append(errs, fmt.Errorf("write csv row for task %s: %w", t.RegistrationInfo.URI, err))
		}
	}

	if report != nil {
		report(3, 3)
	}

	stats["tasks_total"] = len(root.Tasks)
	stats["tasks_high"] = highCount
	stats["tasks_notable"] = notableCount
	stats["tasks_low"] = lowCount

	return []string{csvPath}, stats, errs
}

// isKnownDefenderPlatformBinary reports whether s references MpCmdRun.exe
// from Windows Defender's own versioned platform directory under
// ProgramData — the standard, well-documented location Defender stages its
// own binary updates on every Windows 10/11/Server install with Defender
// enabled. ProgramData is still a genuine suspicious-path signal in general
// (a common attacker drop location, since it's usually writable and less
// scrutinized than Program Files), so this is a narrow allowlist for this
// one specific, universally-legitimate binary rather than a blanket
// exemption for the whole directory. s is expected to already be
// lowercased (see allCmds/allArgs construction above).
func isKnownDefenderPlatformBinary(s string) bool {
	return strings.Contains(s, `\programdata\microsoft\windows defender\platform\`) &&
		strings.Contains(s, "mpcmdrun.exe")
}

func triageTask(uri string, enabled bool, execs []ExecXML, coms []ComHandlerXML, p PrincipalXML) (string, string) {
	var flags []string
	tier := "LOW"

	var allCmds []string
	var allArgs []string
	for _, e := range execs {
		allCmds = append(allCmds, strings.ToLower(e.Command))
		allArgs = append(allArgs, strings.ToLower(e.Arguments))
	}
	for _, c := range coms {
		allCmds = append(allCmds, strings.ToLower(c.ClassId))
		allArgs = append(allArgs, strings.ToLower(c.Data))
	}

	hasSuspiciousPath := false
	hasLolbin := false
	hasEncoded := false

	for _, s := range allCmds {
		if isKnownDefenderPlatformBinary(s) {
			continue
		}
		for _, pathHint := range suspiciousExecPaths {
			if strings.Contains(s, pathHint) {
				hasSuspiciousPath = true
				flags = append(flags, "runs from suspicious path: "+pathHint)
				break
			}
		}
	}
	if !hasSuspiciousPath {
		for _, s := range allArgs {
			if isKnownDefenderPlatformBinary(s) {
				continue
			}
			for _, pathHint := range suspiciousExecPaths {
				if strings.Contains(s, pathHint) {
					hasSuspiciousPath = true
					flags = append(flags, "runs from suspicious path: "+pathHint)
					break
				}
			}
		}
	}

	for _, s := range allCmds {
		for _, lol := range taskLolbins {
			if strings.Contains(s, lol) {
				hasLolbin = true
				flags = append(flags, "LOLBin: "+lol)
				break
			}
		}
	}

	for _, s := range allArgs {
		// hasEncodedMarker is defined in wmi_subscriptions.go (same package).
		if hasEncodedMarker(s) {
			hasEncoded = true
			flags = append(flags, "encoded/obfuscated arguments")
			break
		}
	}

	isStandardWindows := strings.HasPrefix(strings.ToLower(uri), `\microsoft\windows\`)

	if p.UserId == "S-1-5-18" && (hasSuspiciousPath || hasLolbin) {
		flags = append(flags, "runs as SYSTEM with high risk arguments/path")
	}

	if enabled {
		switch {
		case hasSuspiciousPath || hasEncoded:
			tier = "HIGH"
		case hasLolbin && !isStandardWindows:
			tier = "HIGH"
		case hasLolbin && isStandardWindows:
			// A LOLBin invocation alone, from a stock Microsoft-shipped task
			// with a clean path and no encoded arguments, matches hundreds of
			// default Windows/Server maintenance tasks (PcaPatchDbTask,
			// CleanupTemporaryState, Server Manager Performance Monitor, etc.
			// all legitimately call rundll32/cscript from system32). It is not
			// actionable on its own — a suspicious DLL/script target is already
			// caught as HIGH by the path check above — so it stays LOW and
			// browsable via its flag rather than flooding the detections feed.
			// Confirmed against real DC and workstation cases where this branch
			// produced only stock-OS false positives.
			tier = "LOW"
			flags = append(flags, "LOLBin on standard Windows task — verify DLL/script target is legitimate")
		case !isStandardWindows && (len(execs) > 0 || len(coms) > 0):
			// A non-Microsoft task with no suspicious indicator (clean path, no
			// LOLBin, no encoded arguments) is ordinary third-party software —
			// Office, Edge, OneDrive, and OEM utilities all register scheduled
			// tasks. Flagging every one buried the detections feed under dozens
			// of legitimate vendor tasks, so it stays LOW and browsable via its
			// flag rather than raising a NOTABLE detection.
			tier = "LOW"
			flags = append(flags, "third-party task")
		}
	} else {
		switch {
		case hasSuspiciousPath || hasEncoded:
			tier = "NOTABLE"
			flags = append(flags, "staged/disabled task with suspicious indicators")
		case hasLolbin && !isStandardWindows:
			tier = "NOTABLE"
			flags = append(flags, "staged/disabled task with suspicious indicators")
		case hasLolbin && isStandardWindows:
			// A disabled stock Windows task using a LOLBin with a clean path
			// (Automatic-Device-Join, Recovery-Check, Pre-staged app cleanup)
			// is Windows shipping default tasks disabled, not a staged threat —
			// same non-actionable class as the enabled branch above, so LOW.
			tier = "LOW"
			flags = append(flags, "LOLBin on standard Windows task — verify DLL/script target is legitimate")
		}
	}

	if len(flags) == 0 {
		return "LOW", "standard task"
	}
	return tier, strings.Join(flags, "; ")
}

