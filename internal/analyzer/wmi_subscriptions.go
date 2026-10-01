// -----------------------------------------------------------------------------
// DEFENSIVE SECURITY / BLUE-TEAM FORENSICS — DETECTION, NOT ATTACK
//
// This file is part of SAFE, a Windows incident-response forensic tool. Its
// sole purpose is to DETECT and TRIAGE malicious activity so blue-team analysts
// can stop attacks. It does not perform, enable, or facilitate any attack.
//
// This analyzer runs in the analyst's LAB over already-collected WMI event
// subscription listings and detects WMI event-subscription persistence (MITRE
// T1546.003) left behind by an attacker. A "permanent" WMI subscription pairs an
// __EventFilter (a WQL trigger) with an EventConsumer (the action) via a
// __FilterToConsumerBinding; an attacker uses a code-executing consumer
// (CommandLineEventConsumer / ActiveScriptEventConsumer) to run a payload when
// the trigger fires, surviving reboots with no file on disk. This analyzer
// describes that technique only to recognize its forensic footprint so a
// defender can find and remove the persistence. It plants nothing and modifies
// no live system. See the "Defensive Security Charter" in DEV_HISTORY.md.
// -----------------------------------------------------------------------------

package analyzer

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// WmiSubscriptionParser detects WMI event-subscription persistence (MITRE
// T1546.003) from the three Get-CimInstance listings the persistence_core module
// captures on the target: __EventConsumer, __EventFilter, and
// __FilterToConsumerBinding (all under root\subscription). The collection side
// runs a single command per class and saves its Format-List text verbatim; ALL
// interpretation happens here, lab-side.
//
// The forensic signal: Windows ships exactly one permanent subscription by
// default — the "SCM Event Log" filter bound to an NTEventLogEventConsumer,
// which only writes to the event log and cannot execute code. A
// CommandLineEventConsumer or ActiveScriptEventConsumer is the attacker's tool of
// choice for this technique and does not appear on a clean host; a binding that
// drives one is the high-confidence IOC.
type WmiSubscriptionParser struct{}

func (p *WmiSubscriptionParser) Name() string { return "wmi_subscriptions" }

// wmiObject is one parsed Format-List record: a flat map of property name to
// value. Property names are kept as-emitted (PowerShell casing).
type wmiObject map[string]string

// consumer is an EventConsumer registration enriched for triage.
type consumer struct {
	class   string // e.g. CommandLineEventConsumer, NTEventLogEventConsumer
	name    string // the consumer's Name property
	action  string // the code/command this consumer runs, if any (empty for log-only)
	bound   bool   // referenced by at least one binding
	codeExec bool  // class can execute code (CommandLine / ActiveScript)
}

// filter is an __EventFilter registration.
type filter struct {
	name      string
	query     string
	namespace string
	bound     bool
}

// subscription is one row of output: a binding (or an orphan consumer/filter),
// correlated and triaged.
type subscription struct {
	bound         bool // a __FilterToConsumerBinding links these (false = orphan)
	consumerClass string
	consumerName  string
	filterName    string
	filterQuery   string
	namespace     string
	action        string
	tier          string // HIGH / NOTABLE / LOW
	flags         string
}

func (p *WmiSubscriptionParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error

	// Locate the persistence_core module dir. Absent → the parser has nothing to
	// do and reports "skipped" (no outputs, no errors), matching the analyzer's
	// status convention for "source module not in case".
	persistDir := firstGlob(caseDir, filepath.Join("modules", "*_persistence_core"))
	if persistDir == "" {
		return nil, stats, nil
	}
	consumersFile := filepath.Join(persistDir, "wmi_event_consumers.txt")
	filtersFile := filepath.Join(persistDir, "wmi_event_filters.txt")
	bindingsFile := filepath.Join(persistDir, "wmi_filter_to_consumer_bindings.txt")
	// If none of the three listings exist, there is nothing to parse.
	if !anyExist(consumersFile, filtersFile, bindingsFile) {
		return nil, stats, nil
	}

	// Three quick steps (one per listing) drive the analyze bar.
	step := 0
	advance := func() {
		step++
		if report != nil {
			report(step, 3)
		}
	}

	consumerObjs, cerr := parseFormatList(consumersFile)
	if cerr != nil {
		errs = append(errs, fmt.Errorf("read wmi_event_consumers.txt: %w", cerr))
	}
	advance()
	filterObjs, ferr := parseFormatList(filtersFile)
	if ferr != nil {
		errs = append(errs, fmt.Errorf("read wmi_event_filters.txt: %w", ferr))
	}
	advance()
	bindingObjs, berr := parseFormatList(bindingsFile)
	if berr != nil {
		errs = append(errs, fmt.Errorf("read wmi_filter_to_consumer_bindings.txt: %w", berr))
	}
	advance()

	consumers := buildConsumers(consumerObjs)
	filters := buildFilters(filterObjs)

	// Correlate: one subscription per binding, plus orphan consumers/filters that
	// no binding references (a staged or leftover half-subscription).
	var subs []subscription
	for _, b := range bindingObjs {
		cClass, cName := parseRef(b["Consumer"])
		_, fName := parseRef(b["Filter"])

		c := consumers[consumerKey(cClass, cName)]
		f := filters[fName]
		if c != nil {
			c.bound = true
		}
		if f != nil {
			f.bound = true
		}
		subs = append(subs, buildSubscription(true, cClass, cName, fName, c, f))
	}
	// Orphan code-capable consumers (defined but unbound) are still worth
	// surfacing — an attacker may stage the consumer before binding it.
	for _, c := range consumersSorted(consumers) {
		if !c.bound {
			subs = append(subs, buildSubscription(false, c.class, c.name, "", c, nil))
		}
	}
	// Orphan filters (a trigger with no consumer) — low signal but recorded.
	for _, f := range filtersSorted(filters) {
		if !f.bound {
			subs = append(subs, buildSubscription(false, "", "", f.name, nil, f))
		}
	}

	sortSubscriptions(subs)

	outDir := filepath.Join(labReportDir, "wmi_subscriptions")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, append(errs, fmt.Errorf("create output dir: %w", err))
	}

	csvPath := filepath.Join(outDir, "wmi_subscriptions.csv")
	if err := writeWmiCSV(csvPath, subs); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write wmi_subscriptions.csv: %w", err))
	}
	outputs := []string{csvPath}

	summaryPath := filepath.Join(outDir, "summary.txt")
	if err := writeWmiSummary(summaryPath, subs, len(consumers), len(filters), len(bindingObjs)); err != nil {
		errs = append(errs, fmt.Errorf("write summary.txt: %w", err))
	} else {
		outputs = append(outputs, summaryPath)
	}

	high, notable := 0, 0
	for _, s := range subs {
		switch s.tier {
		case "HIGH":
			high++
		case "NOTABLE":
			notable++
		}
	}
	stats["consumers_total"] = len(consumers)
	stats["filters_total"] = len(filters)
	stats["bindings_total"] = len(bindingObjs)
	stats["subscriptions_high"] = high
	stats["subscriptions_notable"] = notable

	return outputs, stats, errs
}

// ---- Format-List parsing -------------------------------------------------

// keyLine matches a PowerShell Format-List property line: "Name : value", with
// the key anchored at the start of the line. Wrapped values continue on indented
// lines and are appended to the previous value.
var keyLine = regexp.MustCompile(`^([A-Za-z0-9_]+)\s+:\s?(.*)$`)

// parseFormatList reads a "Format-List *" capture and returns one wmiObject per
// record. Records are separated by blank lines; within a record, an indented
// continuation line extends the previous property's value. A missing file is not
// an error — it yields zero objects (the class genuinely had no instances, or
// the command produced nothing).
func parseFormatList(path string) ([]wmiObject, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var objects []wmiObject
	cur := wmiObject{}
	lastKey := ""
	flush := func() {
		if len(cur) > 0 {
			objects = append(objects, cur)
			cur = wmiObject{}
			lastKey = ""
		}
	}

	scanner := bufio.NewScanner(f)
	// WQL queries and command templates can be long; raise the line cap.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if m := keyLine.FindStringSubmatch(line); m != nil {
			lastKey = m[1]
			cur[lastKey] = strings.TrimSpace(m[2])
			continue
		}
		// Continuation of the previous property's wrapped value.
		if lastKey != "" {
			cur[lastKey] = strings.TrimSpace(cur[lastKey] + " " + strings.TrimSpace(line))
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return objects, nil
}

// parseRef extracts the class and Name from a binding reference value such as
//
//	CommandLineEventConsumer (Name = "Updater")
//	__EventFilter (Name = "Trigger")
//
// Returns ("", "") if the form is unrecognized.
func parseRef(ref string) (class, name string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", ""
	}
	if i := strings.Index(ref, "("); i >= 0 {
		class = strings.TrimSpace(ref[:i])
	} else {
		class = ref
	}
	if m := nameInRef.FindStringSubmatch(ref); m != nil {
		name = m[1]
	}
	return class, name
}

var nameInRef = regexp.MustCompile(`Name\s*=\s*"([^"]*)"`)

// ---- model building ------------------------------------------------------

func consumerKey(class, name string) string {
	return strings.ToLower(class) + "\x00" + strings.ToLower(name)
}

func buildConsumers(objs []wmiObject) map[string]*consumer {
	out := map[string]*consumer{}
	for _, o := range objs {
		class := classOf(o)
		name := o["Name"]
		c := &consumer{
			class:    class,
			name:     name,
			action:   consumerAction(class, o),
			codeExec: isCodeExecConsumer(class),
		}
		out[consumerKey(class, name)] = c
	}
	return out
}

func buildFilters(objs []wmiObject) map[string]*filter {
	out := map[string]*filter{}
	for _, o := range objs {
		f := &filter{
			name:      o["Name"],
			query:     o["Query"],
			namespace: o["EventNamespace"],
		}
		out[f.name] = f
	}
	return out
}

// classOf returns the leaf class name from a CimClass value like
// "ROOT/subscription:CommandLineEventConsumer".
func classOf(o wmiObject) string {
	cc := o["CimClass"]
	if i := strings.LastIndex(cc, ":"); i >= 0 {
		return strings.TrimSpace(cc[i+1:])
	}
	return strings.TrimSpace(cc)
}

func isCodeExecConsumer(class string) bool {
	switch class {
	case "CommandLineEventConsumer", "ActiveScriptEventConsumer":
		return true
	}
	return false
}

// consumerAction returns the code/command a consumer runs, for the columns and
// for LOLBin/path flagging. Log-only consumers return "".
func consumerAction(class string, o wmiObject) string {
	switch class {
	case "CommandLineEventConsumer":
		cmd := strings.TrimSpace(o["CommandLineTemplate"])
		exe := strings.TrimSpace(o["ExecutablePath"])
		switch {
		case cmd != "" && exe != "":
			return exe + "  " + cmd
		case cmd != "":
			return cmd
		default:
			return exe
		}
	case "ActiveScriptEventConsumer":
		if f := strings.TrimSpace(o["ScriptFileName"]); f != "" {
			return fmt.Sprintf("[%s] %s", strings.TrimSpace(o["ScriptingEngine"]), f)
		}
		return fmt.Sprintf("[%s] %s", strings.TrimSpace(o["ScriptingEngine"]), strings.TrimSpace(o["ScriptText"]))
	}
	return ""
}

// buildSubscription correlates a (consumer, filter) pair into one output row and
// assigns its triage tier and flags.
func buildSubscription(bound bool, cClass, cName, fName string, c *consumer, f *filter) subscription {
	s := subscription{
		bound:         bound,
		consumerClass: cClass,
		consumerName:  cName,
		filterName:    fName,
	}
	if c != nil {
		s.consumerClass = c.class
		s.consumerName = c.name
		s.action = c.action
	}
	if f != nil {
		s.filterName = f.name
		s.filterQuery = f.query
		s.namespace = f.namespace
	}
	triageSubscription(&s, c, f)
	return s
}

// ---- triage --------------------------------------------------------------

// wmiLolbins are interpreters/utilities an attacker commonly invokes from a WMI
// consumer to run a payload.
var wmiLolbins = []string{
	"powershell", "pwsh", "mshta", "rundll32", "regsvr32", "wscript", "cscript",
	"cmd.exe", "cmd ", "certutil", "bitsadmin", "msbuild", "installutil",
	"wmic", "schtasks", "curl", "msiexec",
}

// suspiciousPathHints are directories a legitimate persistent consumer would not
// normally run from.
var suspiciousPathHints = []string{
	`\temp\`, `\appdata\`, `\programdata\`, `\users\public\`, `\windows\temp\`,
	`%temp%`, `%appdata%`, `\downloads\`,
}

// abusedTriggers are WQL trigger fragments frequently used to fire WMI
// persistence (process start, logon, or time-based polling).
var abusedTriggers = []string{
	"win32_processstarttrace", "win32_process", "__instancecreationevent",
	"win32_logonsession", "win32_localtime", "win32_ntlogevent",
	"registrytreechangeevent", "registrykeychangeevent", "__intervaltimerinstruction",
}

func triageSubscription(s *subscription, c *consumer, f *filter) {
	var flags []string

	codeExec := c != nil && c.codeExec
	action := strings.ToLower(s.action)
	query := strings.ToLower(s.filterQuery)

	if codeExec {
		flags = append(flags, "code-executing consumer ("+s.consumerClass+")")
		for _, l := range wmiLolbins {
			if strings.Contains(action, l) {
				flags = append(flags, "LOLBin: "+strings.TrimSpace(l))
				break
			}
		}
		if hasEncodedMarker(action) {
			flags = append(flags, "encoded/obfuscated command")
		}
		for _, h := range suspiciousPathHints {
			if strings.Contains(action, h) {
				flags = append(flags, "runs from suspicious path")
				break
			}
		}
	}

	for _, t := range abusedTriggers {
		if strings.Contains(query, t) {
			flags = append(flags, "trigger: "+t)
			break
		}
	}

	if !s.bound {
		if c != nil {
			flags = append(flags, "consumer not bound to any filter (staged/leftover)")
		} else {
			flags = append(flags, "filter not bound to any consumer")
		}
	}

	// Tiering:
	//   HIGH    — a live binding that drives a code-executing consumer. Windows
	//             ships none of these; presence is the high-confidence IOC.
	//   NOTABLE — a code-exec consumer that is staged (unbound), or any
	//             non-baseline consumer, or a known-abused trigger query.
	//   LOW     — the built-in log-only baseline (NTEventLogEventConsumer).
	switch {
	case s.bound && codeExec:
		s.tier = "HIGH"
	case codeExec:
		s.tier = "NOTABLE" // staged code-exec consumer, not yet bound
	case isBaselineConsumer(s.consumerClass):
		s.tier = "LOW"
	case s.consumerClass != "" || queryIsAbused(query):
		s.tier = "NOTABLE" // unusual but non-code-exec consumer, or abused trigger
	default:
		s.tier = "LOW"
	}

	s.flags = strings.Join(flags, "; ")
}

func hasEncodedMarker(action string) bool {
	for _, m := range []string{" -enc", " -e ", " -ec ", "-encodedcommand", "frombase64string", "[convert]::", "iex ", "invoke-expression", " -w hidden", "-windowstyle hidden", "downloadstring", "downloadfile"} {
		if strings.Contains(action, m) {
			return true
		}
	}
	return false
}

func isBaselineConsumer(class string) bool {
	// NTEventLogEventConsumer only writes to the event log; it cannot run code
	// and is the class of the Windows-default "SCM Event Log" subscription.
	return class == "NTEventLogEventConsumer"
}

func queryIsAbused(query string) bool {
	for _, t := range abusedTriggers {
		if strings.Contains(query, t) {
			return true
		}
	}
	return false
}

// ---- sorting -------------------------------------------------------------

func tierRank(t string) int {
	switch t {
	case "HIGH":
		return 0
	case "NOTABLE":
		return 1
	default:
		return 2
	}
}

func sortSubscriptions(subs []subscription) {
	sort.SliceStable(subs, func(i, j int) bool {
		if tierRank(subs[i].tier) != tierRank(subs[j].tier) {
			return tierRank(subs[i].tier) < tierRank(subs[j].tier)
		}
		if subs[i].consumerName != subs[j].consumerName {
			return subs[i].consumerName < subs[j].consumerName
		}
		return subs[i].filterName < subs[j].filterName
	})
}

func consumersSorted(m map[string]*consumer) []*consumer {
	out := make([]*consumer, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].class != out[j].class {
			return out[i].class < out[j].class
		}
		return out[i].name < out[j].name
	})
	return out
}

func filtersSorted(m map[string]*filter) []*filter {
	out := make([]*filter, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// ---- output --------------------------------------------------------------

func writeWmiCSV(path string, subs []subscription) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"tier", "binding_present", "consumer_class", "consumer_name",
		"filter_name", "event_namespace", "filter_query", "consumer_action", "flags",
	}); err != nil {
		return err
	}
	for _, s := range subs {
		if err := w.Write([]string{
			s.tier,
			boolStr(s.bound),
			s.consumerClass,
			csvSafe(s.consumerName),
			csvSafe(s.filterName),
			s.namespace,
			csvSafe(s.filterQuery),
			csvSafe(s.action),
			s.flags,
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func writeWmiSummary(path string, subs []subscription, consumers, filters, bindings int) error {
	var b strings.Builder
	high, notable, low := 0, 0, 0
	for _, s := range subs {
		switch s.tier {
		case "HIGH":
			high++
		case "NOTABLE":
			notable++
		default:
			low++
		}
	}

	fmt.Fprintf(&b, "wmi_subscriptions analyzer summary\n")
	fmt.Fprintf(&b, "=================================\n\n")
	fmt.Fprintf(&b, "Technique: WMI Event Subscription persistence (MITRE T1546.003)\n\n")
	fmt.Fprintf(&b, "EventConsumers: %d   EventFilters: %d   FilterToConsumerBindings: %d\n", consumers, filters, bindings)
	fmt.Fprintf(&b, "Rows reported: %d  (HIGH %d, NOTABLE %d, LOW %d)\n\n", len(subs), high, notable, low)

	fmt.Fprintf(&b, "HIGH-tier (live binding driving a code-executing consumer):\n")
	if high == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	}
	for _, s := range subs {
		if s.tier != "HIGH" {
			continue
		}
		fmt.Fprintf(&b, "  %s \"%s\"  <-  filter \"%s\"\n      query: %s\n      action: %s\n      %s\n",
			s.consumerClass, s.consumerName, s.filterName, s.filterQuery, s.action, s.flags)
	}

	fmt.Fprintf(&b, "\nNOTABLE-tier (review):\n")
	if notable == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	}
	for _, s := range subs {
		if s.tier != "NOTABLE" {
			continue
		}
		label := s.consumerClass
		if label == "" {
			label = "filter " + s.filterName
		}
		fmt.Fprintf(&b, "  [%s] %s \"%s\"  (%s)\n", s.tier, label, s.consumerName, s.flags)
	}

	fmt.Fprintf(&b, "\nBaseline note: Windows ships one permanent subscription by default — the\n")
	fmt.Fprintf(&b, "\"SCM Event Log\" filter bound to an NTEventLogEventConsumer, which only\n")
	fmt.Fprintf(&b, "writes to the event log and cannot run code (tier LOW). A\n")
	fmt.Fprintf(&b, "CommandLineEventConsumer or ActiveScriptEventConsumer does NOT appear on a\n")
	fmt.Fprintf(&b, "clean host; a binding that drives one is the high-confidence IOC. See\n")
	fmt.Fprintf(&b, "wmi_subscriptions.csv for all rows.\n")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// ---- small helpers -------------------------------------------------------

func anyExist(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
