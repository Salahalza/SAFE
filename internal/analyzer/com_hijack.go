package analyzer

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"www.velocidex.com/golang/regparser"
)

// ComHijackParser detects COM-hijacking persistence (MITRE T1546.015) by
// parsing the collected registry hives lab-side. It is the COM half of the
// deferred Phase 2 lab work.
//
// Why this is a lab parser, not a collection module: per-user COM registrations
// live under HKCU\Software\Classes\CLSID, which is backed by the user's
// UsrClass.dat hive — not reachable by a single on-target `reg query` without
// loading every user's hive (noisy, and impossible for logged-off users). The
// collection side simply copies SOFTWARE + each user's UsrClass.dat; the
// hijack reasoning happens here.
//
// How COM hijacking works: a COM object is resolved by CLSID. The server
// (InprocServer32 = in-process DLL, LocalServer32 = out-of-process EXE) is
// looked up in HKEY_CLASSES_ROOT, which is a MERGE of HKLM\Software\Classes and
// HKCU\Software\Classes with HKCU taking precedence. An attacker who plants
// HKCU\Software\Classes\CLSID\{guid}\InprocServer32 pointing at a malicious DLL
// hijacks a CLSID the system would otherwise resolve from HKLM — with no admin
// rights. The strong signal is therefore a per-user CLSID that SHADOWS an
// HKLM CLSID with a DIFFERENT module path.
//
// Scope (and why): the parser inventories the PER-USER hijack surface (every
// UsrClass.dat CLSID server) and uses HKLM SOFTWARE purely as a SHADOW ORACLE —
// it indexes the set of HKLM CLSID GUIDs once (a fast one-level enumeration) and
// resolves an HKLM module path on demand only for the handful of user CLSIDs
// that actually shadow one. It deliberately does NOT deep-walk all ~12k HKLM
// CLSID servers: that walk cost minutes on a field VM and only surfaced benign
// system noise (the documented threat model is per-user hijacking). HKLM-side
// COM implants require admin and are out of this parser's scope.
//
// Triage tiers (the triage_tier column):
//   - HIGH:    a user CLSID shadows an HKLM CLSID with a different module path
//     (the override hijack pattern).
//   - NOTABLE: a server in a user-writable / non-standard path, a script /
//     scriptlet server module, a LOLBin server command, a TreatAs redirection,
//     or a user CLSID that shadows HKLM with the SAME path (redundant, unusual).
//   - LOW:     everything else (e.g. ordinary per-user shell extensions).
//
// NOTE on false positives: legitimate per-user apps (OneDrive, Teams, Slack)
// register COM servers under AppData. Those are user-only (they do not shadow
// HKLM), so they land in NOTABLE at most, never HIGH. The summary says so
// explicitly so the analyst is not misled by an AppData path alone.
type ComHijackParser struct{}

func (p *ComHijackParser) Name() string { return "com_hijack" }

// comServer is one per-user CLSID server registration discovered in a
// UsrClass.dat hive, enriched with hijack flags.
type comServer struct {
	sid             string // user SID
	clsid           string // {GUID}, upper-cased
	friendlyName    string // default value of the CLSID key, if any
	wow64           bool   // came from a Wow6432Node\CLSID subtree
	serverType      string // InprocServer32 / LocalServer32
	modulePath      string // default value of the server key
	threadingModel  string // ThreadingModel value (Inproc only)
	treatAs         bool   // a TreatAs subkey is present
	suspiciousPath  bool
	badServerExt    bool // server module is a script/scriptlet type
	lolbin          bool // a living-off-the-land binary appears in the server command
	shadowsHKLM     bool
	hklmPathDiffers bool
	tier            string
	flags           string
}

func (p *ComHijackParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error

	// Locate sources. Either may be absent; if BOTH are absent the parser has
	// nothing to do and reports "skipped" (no outputs, no errors).
	softwareHive := firstGlob(caseDir, filepath.Join("modules", "*_registry_core", "HKLM_SOFTWARE.hiv"))
	userHivesRoot := firstGlob(caseDir, filepath.Join("modules", "*_user_hives_collection"))
	if softwareHive == "" && userHivesRoot == "" {
		return nil, stats, nil
	}

	// Pre-list the user hives so the progress total is known up front. Indexing
	// the HKLM hive is by far the slow step (a large hive read), so it gets two
	// milestones (one per CLSID view) and each user hive gets one — this keeps
	// the analyze bar moving through the multi-second HKLM index.
	var userSIDs []string
	if userHivesRoot != "" {
		userDirs, derr := os.ReadDir(userHivesRoot)
		if derr != nil {
			errs = append(errs, fmt.Errorf("read user hives root: %w", derr))
		}
		for _, ud := range userDirs {
			if !ud.IsDir() {
				continue
			}
			sid := ud.Name()
			if _, serr := os.Stat(filepath.Join(userHivesRoot, sid, "UsrClass.dat")); serr != nil {
				continue
			}
			userSIDs = append(userSIDs, sid)
		}
	}

	totalSteps := len(userSIDs)
	if softwareHive != "" {
		totalSteps += 2 // one milestone per HKLM CLSID view (64-bit, Wow6432Node)
	}
	step := 0
	advance := func() {
		step++
		if report != nil {
			report(step, totalSteps)
		}
	}

	// HKLM shadow oracle. Index the HKLM CLSID GUID set once (fast, one-level),
	// keeping the registry open so shadowing user CLSIDs can resolve an HKLM
	// path on demand. 64-bit (Classes\CLSID) and 32-bit (Wow6432Node) are kept
	// separate so a user 32-bit CLSID is only matched against HKLM 32-bit.
	var oracle *hklmOracle
	if softwareHive != "" {
		o, swFile, oerr := openHKLMOracle(softwareHive, advance)
		if oerr != nil {
			errs = append(errs, fmt.Errorf("HKLM SOFTWARE: %w", oerr))
		} else {
			defer swFile.Close()
			oracle = o
		}
	}

	// Collect every per-user CLSID server (the hijack surface).
	var userServers []comServer
	usersParsed := 0
	for _, sid := range userSIDs {
		usrClass := filepath.Join(userHivesRoot, sid, "UsrClass.dat")
		usersParsed++
		servers, perr := readUserServers(usrClass, sid)
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s UsrClass.dat: %w", sid, perr))
			advance()
			continue
		}
		userServers = append(userServers, servers...)
		advance()
	}

	for i := range userServers {
		flagUserServer(&userServers[i], oracle)
	}
	sortServers(userServers)

	outDir := filepath.Join(labReportDir, "com_hijack")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, append(errs, fmt.Errorf("create output dir: %w", err))
	}

	csvPath := filepath.Join(outDir, "com_servers.csv")
	if err := writeComCSV(csvPath, userServers); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write com_servers.csv: %w", err))
	}
	outputs := []string{csvPath}

	hklmIndexed := 0
	if oracle != nil {
		hklmIndexed = oracle.count()
	}
	summaryPath := filepath.Join(outDir, "summary.txt")
	if err := writeComSummary(summaryPath, userServers, hklmIndexed, usersParsed, oracle != nil); err != nil {
		errs = append(errs, fmt.Errorf("write summary.txt: %w", err))
	} else {
		outputs = append(outputs, summaryPath)
	}

	high, notable := 0, 0
	for _, s := range userServers {
		switch s.tier {
		case "HIGH":
			high++
		case "NOTABLE":
			notable++
		}
	}
	stats["users_parsed"] = usersParsed
	stats["hklm_clsids_indexed"] = hklmIndexed
	stats["user_servers"] = len(userServers)
	stats["servers_high"] = high
	stats["servers_notable"] = notable

	return outputs, stats, errs
}

// ---- HKLM shadow oracle --------------------------------------------------

// hklmOracle answers two questions cheaply: does an HKLM CLSID exist (set
// membership, no I/O), and what is its server module path (a single targeted
// OpenKey, done only for confirmed shadows).
type hklmOracle struct {
	reg   *regparser.Registry
	set64 map[string]bool // Classes\CLSID GUIDs, upper-cased
	set32 map[string]bool // Classes\Wow6432Node\CLSID GUIDs, upper-cased
}

// openHKLMOracle opens the SOFTWARE hive and indexes the CLSID GUID sets. The
// caller must keep the returned file open (and close it) for the oracle's
// lifetime — regparser reads lazily from it. afterSet, if non-nil, is called
// after each CLSID view is indexed (this is the slow step, so it drives the
// analyze bar forward mid-parse).
func openHKLMOracle(hivePath string, afterSet func()) (*hklmOracle, *os.File, error) {
	f, err := os.Open(hivePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open: %w", err)
	}
	reg, err := regparser.NewRegistry(f)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("parse: %w", err)
	}
	o := &hklmOracle{reg: reg}
	o.set64 = clsidNameSet(reg, `Classes\CLSID`)
	if afterSet != nil {
		afterSet()
	}
	o.set32 = clsidNameSet(reg, `Classes\Wow6432Node\CLSID`)
	if afterSet != nil {
		afterSet()
	}
	return o, f, nil
}

func (o *hklmOracle) count() int { return len(o.set64) + len(o.set32) }

// has reports whether the CLSID exists in HKLM (membership only, no I/O).
func (o *hklmOracle) has(clsid string, wow64 bool) bool {
	set := o.set64
	if wow64 {
		set = o.set32
	}
	return set[strings.ToUpper(clsid)]
}

// serverPath resolves the HKLM module path for a CLSID's server type with a
// single targeted OpenKey. Called only for confirmed shadows, so the per-call
// cost (an index traversal) is paid a handful of times, not ~12k.
func (o *hklmOracle) serverPath(clsid, serverType string, wow64 bool) (string, bool) {
	base := `Classes\CLSID\`
	if wow64 {
		base = `Classes\Wow6432Node\CLSID\`
	}
	k := o.reg.OpenKey(base + clsid + `\` + serverType)
	if k == nil {
		return "", false
	}
	return defaultValue(k), true
}

// clsidNameSet enumerates the immediate child key names of a CLSID container
// into an upper-cased set. This is the fast one-level read (no descent into
// each CLSID's subkeys/values) that replaces the old deep walk.
func clsidNameSet(reg *regparser.Registry, path string) map[string]bool {
	set := map[string]bool{}
	root := reg.OpenKey(path)
	if root == nil {
		return set
	}
	for _, s := range root.Subkeys() {
		set[strings.ToUpper(s.Name())] = true
	}
	return set
}

// ---- user hive reading ---------------------------------------------------

// readUserServers reads server registrations from a user's UsrClass.dat (the
// HKCU\Software\Classes backing hive). The CLSID subtrees are top-level here.
func readUserServers(hivePath, sid string) ([]comServer, error) {
	f, err := os.Open(hivePath)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	var servers []comServer
	for _, sub := range []struct {
		path  string
		wow64 bool
	}{
		{`CLSID`, false},
		{`Wow6432Node\CLSID`, true},
	} {
		root := reg.OpenKey(sub.path)
		if root == nil {
			continue
		}
		servers = append(servers, collectCLSIDServers(root, sid, sub.wow64)...)
	}
	return servers, nil
}

// collectCLSIDServers walks a CLSID container key and emits one comServer per
// InprocServer32 / LocalServer32 registration found under each {guid} subkey.
func collectCLSIDServers(clsidRoot *regparser.CM_KEY_NODE, sid string, wow64 bool) []comServer {
	var servers []comServer
	for _, guidKey := range clsidRoot.Subkeys() {
		clsid := guidKey.Name()
		friendly := defaultValue(guidKey)

		// Single pass over the {guid} subkeys: note TreatAs, collect servers.
		var treatAs bool
		var serverKeys []*regparser.CM_KEY_NODE
		for _, c := range guidKey.Subkeys() {
			switch {
			case strings.EqualFold(c.Name(), "TreatAs"):
				treatAs = true
			case strings.EqualFold(c.Name(), "InprocServer32"),
				strings.EqualFold(c.Name(), "LocalServer32"):
				serverKeys = append(serverKeys, c)
			}
		}

		for _, c := range serverKeys {
			s := comServer{
				sid:          sid,
				clsid:        strings.ToUpper(clsid),
				friendlyName: friendly,
				wow64:        wow64,
				serverType:   c.Name(),
				modulePath:   defaultValue(c),
				treatAs:      treatAs,
			}
			if strings.EqualFold(c.Name(), "InprocServer32") {
				s.threadingModel = namedValue(c, "ThreadingModel")
			}
			servers = append(servers, s)
		}
	}
	return servers
}

// defaultValue returns a key's default (unnamed) value as a string, "" if none.
func defaultValue(k *regparser.CM_KEY_NODE) string {
	for _, v := range k.Values() {
		if v.ValueName() == "" {
			return strings.TrimRight(v.ValueData().String, "\x00")
		}
	}
	return ""
}

// namedValue returns a named REG_SZ value as a string, "" if absent.
func namedValue(k *regparser.CM_KEY_NODE, name string) string {
	for _, v := range k.Values() {
		if strings.EqualFold(v.ValueName(), name) {
			return strings.TrimRight(v.ValueData().String, "\x00")
		}
	}
	return ""
}

// ---- flagging / tiering --------------------------------------------------

func flagUserServer(s *comServer, oracle *hklmOracle) {
	var flags []string

	if oracle != nil && oracle.has(s.clsid, s.wow64) {
		s.shadowsHKLM = true
		hklmPath, ok := oracle.serverPath(s.clsid, s.serverType, s.wow64)
		if !ok || !pathEqual(s.modulePath, hklmPath) {
			s.hklmPathDiffers = true
			flags = append(flags, "shadows HKLM CLSID with different path (override hijack)")
		} else {
			flags = append(flags, "shadows HKLM CLSID (same path)")
		}
	}

	flags = append(flags, pathFlags(s)...)
	if s.treatAs {
		flags = append(flags, "TreatAs redirection present")
	}

	s.tier = tierFor(s)
	s.flags = strings.Join(flags, "; ")
}

// tierFor derives the triage tier from the flags already set on the server.
func tierFor(s *comServer) string {
	if s.shadowsHKLM && s.hklmPathDiffers {
		return "HIGH"
	}
	if s.shadowsHKLM || s.suspiciousPath || s.badServerExt || s.lolbin || s.treatAs {
		return "NOTABLE"
	}
	return "LOW"
}

// pathFlags inspects the module path and sets the path-derived booleans on the
// server, returning human-readable flag strings.
func pathFlags(s *comServer) []string {
	var flags []string
	expanded := expandPath(s.modulePath)
	clean := strings.Trim(strings.TrimSpace(expanded), `"`)
	lower := strings.ToLower(clean)

	if clean == "" {
		s.suspiciousPath = true
		return append(flags, "empty server path")
	}

	// User-writable / non-standard locations.
	for _, marker := range userWritableMarkers {
		if strings.Contains(lower, marker) {
			s.suspiciousPath = true
			flags = append(flags, "server in user-writable path ("+strings.Trim(marker, `\`)+")")
			break
		}
	}

	// Unqualified module name (no path separator, no drive) — resolved via the
	// loader search order, a classic hijack trick.
	if !strings.Contains(clean, `\`) && !strings.Contains(clean, "/") {
		s.suspiciousPath = true
		flags = append(flags, "unqualified module name (search-order resolved)")
	}

	// Script / scriptlet server module — never a legitimate COM server type.
	if ext := moduleExt(lower); ext != "" && scriptExts[ext] {
		s.badServerExt = true
		flags = append(flags, "script/scriptlet server module ("+ext+")")
	}

	// LOLBin server commands (powershell/mshta/rundll32/...).
	for _, bin := range lolbins {
		if strings.Contains(lower, bin) {
			s.lolbin = true
			flags = append(flags, "LOLBin in server command ("+bin+")")
			break
		}
	}

	return flags
}

var userWritableMarkers = []string{
	`\appdata\`, `\temp\`, `\tmp\`, `\programdata\`,
	`\users\public\`, `\downloads\`, `\roaming\`, `\local\temp\`,
}

var lolbins = []string{
	"rundll32", "regsvr32", "mshta", "powershell", "wscript",
	"cscript", "certutil", "scrobj.dll",
}

// scriptExts are extensions that are never a legitimate COM server module —
// their presence as a server is the scriptlet/script-hijack signature.
var scriptExts = map[string]bool{
	".sct": true, ".js": true, ".jse": true, ".vbs": true, ".vbe": true,
	".wsf": true, ".wsh": true, ".ps1": true, ".hta": true, ".bat": true,
	".cmd": true, ".scr": true,
}

// moduleExt returns the lower-cased extension of the module path, taking only
// the first token (LocalServer32 commands may carry arguments).
func moduleExt(lowerPath string) string {
	field := lowerPath
	if i := strings.IndexByte(field, ' '); i >= 0 {
		field = field[:i]
	}
	dot := strings.LastIndexByte(field, '.')
	slash := strings.LastIndexAny(field, `\/`)
	if dot <= slash || dot < 0 {
		return ""
	}
	return field[dot:]
}

// expandPath expands the common environment placeholders seen in COM server
// paths so the path heuristics see a concrete location.
func expandPath(p string) string {
	repl := strings.NewReplacer(
		"%SystemRoot%", `C:\Windows`, "%systemroot%", `C:\Windows`,
		"%windir%", `C:\Windows`, "%WinDir%", `C:\Windows`,
	)
	return repl.Replace(p)
}

// pathEqual compares two server paths after normalization (env expansion, quote
// and whitespace trim, case fold).
func pathEqual(a, b string) bool { return normalizePath(a) == normalizePath(b) }

func normalizePath(p string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(expandPath(p)), `"`))
}

// ---- output --------------------------------------------------------------

func sortServers(servers []comServer) {
	rank := map[string]int{"HIGH": 0, "NOTABLE": 1, "LOW": 2}
	sort.SliceStable(servers, func(i, j int) bool {
		a, b := servers[i], servers[j]
		if rank[a.tier] != rank[b.tier] {
			return rank[a.tier] < rank[b.tier]
		}
		if a.sid != b.sid {
			return a.sid < b.sid
		}
		return a.clsid < b.clsid
	})
}

func writeComCSV(path string, servers []comServer) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"triage_tier", "sid", "clsid", "friendly_name", "wow64",
		"server_type", "module_path", "threading_model", "treatas",
		"suspicious_path", "shadows_hklm", "hklm_path_differs", "flags",
	}); err != nil {
		return err
	}
	for _, s := range servers {
		if err := w.Write([]string{
			s.tier, s.sid, s.clsid, s.friendlyName,
			strconv.FormatBool(s.wow64), s.serverType, s.modulePath,
			s.threadingModel, strconv.FormatBool(s.treatAs),
			strconv.FormatBool(s.suspiciousPath), strconv.FormatBool(s.shadowsHKLM),
			strconv.FormatBool(s.hklmPathDiffers), s.flags,
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func writeComSummary(path string, servers []comServer, hklmIndexed, usersParsed int, hadHKLM bool) error {
	var b strings.Builder
	high, notable, low := 0, 0, 0
	for _, s := range servers {
		switch s.tier {
		case "HIGH":
			high++
		case "NOTABLE":
			notable++
		default:
			low++
		}
	}

	fmt.Fprintf(&b, "com_hijack analyzer summary\n")
	fmt.Fprintf(&b, "==========================\n\n")
	fmt.Fprintf(&b, "User hives parsed (UsrClass.dat): %d\n", usersParsed)
	if hadHKLM {
		fmt.Fprintf(&b, "HKLM SOFTWARE CLSIDs indexed (shadow oracle): %d\n", hklmIndexed)
	} else {
		fmt.Fprintf(&b, "HKLM SOFTWARE hive not in case: shadow detection unavailable.\n")
	}
	fmt.Fprintf(&b, "Per-user servers reported: %d  (HIGH %d, NOTABLE %d, LOW %d)\n\n", len(servers), high, notable, low)

	fmt.Fprintf(&b, "HIGH-tier (user CLSID overrides an HKLM CLSID with a different path):\n")
	if high == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	}
	for _, s := range servers {
		if s.tier != "HIGH" {
			continue
		}
		fmt.Fprintf(&b, "  %s %s %s%s\n      -> %s\n      %s\n",
			s.sid, s.clsid, s.serverType, wowTag(s.wow64), s.modulePath, s.flags)
	}

	fmt.Fprintf(&b, "\nNOTABLE-tier (review):\n")
	if notable == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	}
	for _, s := range servers {
		if s.tier != "NOTABLE" {
			continue
		}
		fmt.Fprintf(&b, "  [%s] %s %s%s -> %s  (%s)\n",
			s.sid, s.clsid, s.serverType, wowTag(s.wow64), s.modulePath, s.flags)
	}

	fmt.Fprintf(&b, "\nScope: HKLM SOFTWARE is used only as a shadow oracle (which CLSIDs\n")
	fmt.Fprintf(&b, "exist machine-wide); it is not deep-scanned for its own anomalies. The\n")
	fmt.Fprintf(&b, "per-user CLSID surface (UsrClass.dat) is the COM-hijack target.\n\n")
	fmt.Fprintf(&b, "Note: legitimate per-user apps (OneDrive, Teams, Slack) register COM\n")
	fmt.Fprintf(&b, "servers under AppData. Those are user-only and do NOT shadow HKLM, so an\n")
	fmt.Fprintf(&b, "AppData path alone lands in NOTABLE, never HIGH. Confirm the module's\n")
	fmt.Fprintf(&b, "signature/owner before escalating. See com_servers.csv for all rows.\n")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func wowTag(wow64 bool) string {
	if wow64 {
		return " (wow64)"
	}
	return ""
}

// ---- small helpers -------------------------------------------------------

// firstGlob returns the first match of pattern under base, or "".
func firstGlob(base, pattern string) string {
	matches, err := filepath.Glob(filepath.Join(base, pattern))
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}
