package behavior

import (
	"fmt"
	"path"
	"github.com/Salahalza/SAFE/internal/csvutil"
	"sort"
	"strings"
)

// IIS web-server threat-hunt rules. They consume the CSVs produced by the IIS
// analyzer parser (iis/web_files.csv and iis/iis_requests.csv) and surface the
// web-compromise story an analyst cares about first: a shell dropped into a web
// root, and whether it was actually reached over HTTP.
//
// These are detection rules over already-collected evidence — they interpret
// nothing on a live target. Web shells (MITRE T1505.003) and command execution
// through them (T1059) are named as detection vocabulary, exactly as in a Sigma
// rule or EDR alert.

// scriptExtsForRequests is the set of server-executable extensions a request URI
// can target. Used to keep the LOLBin-in-request rule focused on hits against
// actual script resources rather than static content.
var scriptExtsForRequests = map[string]bool{
	".aspx": true, ".asmx": true, ".ashx": true, ".asax": true, ".ascx": true,
	".cshtml": true, ".asp": true, ".php": true, ".php3": true, ".php4": true,
	".php5": true, ".phtml": true, ".jsp": true, ".jspx": true, ".pl": true, ".cgi": true,
}

// --- IIS-01: Web-shell file dropped in a web root ---
type IISWebShellFile struct{}

func (r *IISWebShellFile) ID() string       { return "IIS-01" }
func (r *IISWebShellFile) Name() string     { return "Web Shell in IIS Web Root" }
func (r *IISWebShellFile) MITRE() string    { return "T1505.003" }
func (r *IISWebShellFile) Severity() string { return SeverityHigh }
func (r *IISWebShellFile) Evaluate(dir string) []Hit {
	var hits []Hit
	p := path.Join(dir, "iis", "web_files.csv")
	_ = csvutil.ReadCSVHelper(p, func(header, row []string) error {
		triageIdx := csvutil.GetColIndex(header, "triage")
		nameIdx := csvutil.GetColIndex(header, "filename")
		relIdx := csvutil.GetColIndex(header, "relative_path")
		indIdx := csvutil.GetColIndex(header, "indicators")
		shaIdx := csvutil.GetColIndex(header, "sha256")
		if triageIdx == -1 || nameIdx == -1 {
			return nil
		}

		// Trust the parser's triage (mirrors how B-01 trusts the scheduled-task
		// tier): the parser already weighed strong vs weak indicator tokens.
		var severity string
		switch strings.ToUpper(row[triageIdx]) {
		case "HIGH":
			severity = SeverityHigh
		case "NOTABLE":
			severity = SeverityNotable
		default:
			return nil
		}

		name := row[nameIdx]
		rel := name
		if relIdx != -1 && row[relIdx] != "" {
			rel = row[relIdx]
		}
		inds := ""
		if indIdx != -1 {
			inds = row[indIdx]
		}
		sha := ""
		if shaIdx != -1 {
			sha = row[shaIdx]
		}

		hits = append(hits, Hit{
			RuleID:            r.ID(),
			Severity:          severity,
			MITRE:             r.MITRE(),
			Title:             r.Name(),
			EvidenceSource:    "iis/web_files.csv",
			EvidenceDetail:    fmt.Sprintf("Script '%s' carries web-shell indicators [%s] (sha256 %s)", rel, inds, sha),
			TimelineSearchKey: name,
		})
		return nil
	})
	return hits
}

// --- IIS-02: A flagged web shell was actually requested over HTTP ---
// Correlates the flagged files from web_files.csv with the request log. A shell
// that was reached is a materially stronger finding than one merely present, and
// the request rows give the analyst the client IPs and timing to scope it.
type IISWebShellAccess struct{}

func (r *IISWebShellAccess) ID() string       { return "IIS-02" }
func (r *IISWebShellAccess) Name() string     { return "Web Shell Accessed Over HTTP" }
func (r *IISWebShellAccess) MITRE() string    { return "T1505.003" }
func (r *IISWebShellAccess) Severity() string { return SeverityHigh }
func (r *IISWebShellAccess) Evaluate(dir string) []Hit {
	// 1. Collect the basenames of files flagged above INFO in web_files.csv,
	//    keyed to their triage so an accessed file is reported at the severity it
	//    was flagged — an accessed HIGH shell is HIGH, an accessed NOTABLE file
	//    stays NOTABLE rather than being escalated just for being requested.
	flagged := map[string]string{}
	_ = csvutil.ReadCSVHelper(path.Join(dir, "iis", "web_files.csv"), func(header, row []string) error {
		triageIdx := csvutil.GetColIndex(header, "triage")
		nameIdx := csvutil.GetColIndex(header, "filename")
		if triageIdx == -1 || nameIdx == -1 {
			return nil
		}
		if t := strings.ToUpper(row[triageIdx]); t == "HIGH" || t == "NOTABLE" {
			flagged[strings.ToLower(row[nameIdx])] = t
		}
		return nil
	})
	if len(flagged) == 0 {
		return nil
	}

	// 2. Aggregate requests whose URI targets one of those files.
	type agg struct {
		count     int
		clients   map[string]bool
		methods   map[string]bool
		firstTime string
		lastTime  string
	}
	seen := map[string]*agg{}
	_ = csvutil.ReadCSVHelper(path.Join(dir, "iis", "iis_requests.csv"), func(header, row []string) error {
		stemIdx := csvutil.GetColIndex(header, "uri_stem")
		methodIdx := csvutil.GetColIndex(header, "method")
		clientIdx := csvutil.GetColIndex(header, "client_ip")
		timeIdx := csvutil.GetColIndex(header, "datetime_utc")
		if stemIdx == -1 {
			return nil
		}
		base := uriBase(row[stemIdx])
		if base == "" || flagged[strings.ToLower(base)] == "" {
			return nil
		}
		a := seen[base]
		if a == nil {
			a = &agg{clients: map[string]bool{}, methods: map[string]bool{}}
			seen[base] = a
		}
		a.count++
		if clientIdx != -1 && row[clientIdx] != "" {
			a.clients[row[clientIdx]] = true
		}
		if methodIdx != -1 && row[methodIdx] != "" {
			a.methods[row[methodIdx]] = true
		}
		if timeIdx != -1 && row[timeIdx] != "" {
			ts := row[timeIdx]
			if a.firstTime == "" || ts < a.firstTime {
				a.firstTime = ts
			}
			if ts > a.lastTime {
				a.lastTime = ts
			}
		}
		return nil
	})

	var hits []Hit
	for base, a := range seen {
		severity := SeverityNotable
		if flagged[strings.ToLower(base)] == "HIGH" {
			severity = SeverityHigh
		}
		hits = append(hits, Hit{
			RuleID:         r.ID(),
			Severity:       severity,
			MITRE:          r.MITRE(),
			Title:          r.Name(),
			EvidenceSource: "iis/iis_requests.csv + iis/web_files.csv",
			EvidenceDetail: fmt.Sprintf("Flagged script '%s' requested %d time(s) [%s] from %s between %s and %s",
				base, a.count, joinSet(a.methods), joinSet(a.clients), a.firstTime, a.lastTime),
			TimelineSearchKey: base,
		})
	}
	sortHitsByKey(hits)
	return hits
}

// --- IIS-03: LOLBin name passed to a script resource in the query string ---
// A request to a .aspx/.php/... whose query string carries a living-off-the-land
// binary name is a common shape of command-passing to a web shell. Kept NOTABLE
// and scoped to script resources to bound false positives.
type IISLolBinRequest struct{}

func (r *IISLolBinRequest) ID() string       { return "IIS-03" }
func (r *IISLolBinRequest) Name() string     { return "LOLBin Referenced in IIS Request" }
func (r *IISLolBinRequest) MITRE() string    { return "T1059" }
func (r *IISLolBinRequest) Severity() string { return SeverityNotable }
func (r *IISLolBinRequest) Evaluate(dir string) []Hit {
	lolbins := []string{
		"cmd.exe", "powershell", "certutil", "bitsadmin", "whoami",
		"net user", "net localgroup", "rundll32", "regsvr32", "mshta",
		"wscript", "cscript", "systeminfo", "tasklist", "nltest", "vssadmin",
	}
	type agg struct {
		count int
		tokens map[string]bool
	}
	seen := map[string]*agg{}
	_ = csvutil.ReadCSVHelper(path.Join(dir, "iis", "iis_requests.csv"), func(header, row []string) error {
		stemIdx := csvutil.GetColIndex(header, "uri_stem")
		queryIdx := csvutil.GetColIndex(header, "uri_query")
		if stemIdx == -1 || queryIdx == -1 {
			return nil
		}
		stem := row[stemIdx]
		query := strings.ToLower(row[queryIdx])
		if query == "" {
			return nil
		}
		ext := strings.ToLower(path.Ext(uriBase(stem)))
		if !scriptExtsForRequests[ext] {
			return nil
		}
		for _, lb := range lolbins {
			if strings.Contains(query, lb) {
				a := seen[stem]
				if a == nil {
					a = &agg{tokens: map[string]bool{}}
					seen[stem] = a
				}
				a.count++
				a.tokens[lb] = true
			}
		}
		return nil
	})

	var hits []Hit
	for stem, a := range seen {
		hits = append(hits, Hit{
			RuleID:            r.ID(),
			Severity:          r.Severity(),
			MITRE:             r.MITRE(),
			Title:             r.Name(),
			EvidenceSource:    "iis/iis_requests.csv",
			EvidenceDetail:    fmt.Sprintf("Request to script '%s' carried LOLBin token(s) [%s] in the query string across %d request(s)", stem, joinSet(a.tokens), a.count),
			TimelineSearchKey: uriBase(stem),
		})
	}
	sortHitsByKey(hits)
	return hits
}

// --- Exchange web-surface exploitation (ProxyLogon / ProxyShell family) ---
//
// These rules hunt the IIS request-log traces of the 2021–2022 Exchange
// on-prem exploitation chains (CVE-2021-26855 ProxyLogon, CVE-2021-34473
// ProxyShell, CVE-2022-41040 ProxyNotShell — MITRE T1190). The signatures were
// tuned against a real, clean, patched Exchange server's 51k request rows so the
// discriminators survive genuine Exchange traffic: naive textbook patterns
// (`@` in the query, the string "proxylogon", any `/powershell` access, any
// `autodiscover.json`) all fire thousands of times on a healthy box and are
// deliberately avoided here.

// exchangeInternalClient reports whether a request's client IP is the Exchange
// server talking to itself (health probes, front-end→back-end proxying) rather
// than an attributable remote caller. An empty c-ip (proxied/internal request
// with no recorded client) counts as internal, as do loopback and link-local.
// A routable address — including RFC1918, so lateral movement from an internal
// pivot still alerts — is treated as remote.
func exchangeInternalClient(ip string) bool {
	if ip == "" {
		return true
	}
	ip = strings.ToLower(ip)
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}
	return strings.HasPrefix(ip, "fe80") // IPv6 link-local
}

func isAnonUser(u string) bool {
	return u == "" || strings.EqualFold(u, "anonymous")
}

// proxyShellBackendTokens are the back-end targets that appear in the query of a
// ProxyShell/ProxyLogon SSRF against autodiscover.json. Legitimate AutoDiscover
// V2 (which does use autodiscover.json) carries only Email/Protocol values, none
// of these, so requiring one of these tokens keeps the rule off real traffic.
var proxyShellBackendTokens = []string{
	"powershell", "x-rps-cat", "email=autodiscover", "x-beresource", "/mapi/emsmdb",
}

// --- IIS-04: ProxyShell autodiscover SSRF ---
type IISProxyShellSSRF struct{}

func (r *IISProxyShellSSRF) ID() string       { return "IIS-04" }
func (r *IISProxyShellSSRF) Name() string     { return "Exchange ProxyShell Autodiscover SSRF" }
func (r *IISProxyShellSSRF) MITRE() string    { return "T1190" }
func (r *IISProxyShellSSRF) Severity() string { return SeverityHigh }
func (r *IISProxyShellSSRF) Evaluate(dir string) []Hit {
	type agg struct {
		count             int
		sample            string
		firstTime, lastTime string
	}
	seen := map[string]*agg{}
	_ = csvutil.ReadCSVHelper(path.Join(dir, "iis", "iis_requests.csv"), func(header, row []string) error {
		stem := strings.ToLower(csvutil.SafeIndex(row, csvutil.GetColIndex(header, "uri_stem")))
		query := strings.ToLower(csvutil.SafeIndex(row, csvutil.GetColIndex(header, "uri_query")))
		if !strings.Contains(stem, "autodiscover.json") {
			return nil
		}
		if !containsAny(query, proxyShellBackendTokens) {
			return nil
		}
		client := csvutil.SafeIndex(row, csvutil.GetColIndex(header, "client_ip"))
		key := client
		if key == "" {
			key = "-"
		}
		a := seen[key]
		if a == nil {
			a = &agg{sample: csvutil.SafeIndex(row, csvutil.GetColIndex(header, "uri_query"))}
			seen[key] = a
		}
		a.count++
		updateWindow(&a.firstTime, &a.lastTime, csvutil.SafeIndex(row, csvutil.GetColIndex(header, "datetime_utc")))
		return nil
	})

	var hits []Hit
	for client, a := range seen {
		hits = append(hits, Hit{
			RuleID:         r.ID(),
			Severity:       r.Severity(),
			MITRE:          r.MITRE(),
			Title:          r.Name(),
			EvidenceSource: "iis/iis_requests.csv",
			EvidenceDetail: fmt.Sprintf("autodiscover.json SSRF to an Exchange back end from %s: %d request(s) between %s and %s (query: %s)",
				client, a.count, a.firstTime, a.lastTime, a.sample),
			TimelineSearchKey: "autodiscover.json",
		})
	}
	sortHitsByKey(hits)
	return hits
}

// --- IIS-05: Anonymous access to the Exchange PowerShell back end from a remote client ---
type IISAnonPowerShell struct{}

func (r *IISAnonPowerShell) ID() string       { return "IIS-05" }
func (r *IISAnonPowerShell) Name() string     { return "Anonymous Exchange PowerShell Access (ProxyShell RCE)" }
func (r *IISAnonPowerShell) MITRE() string    { return "T1190" }
func (r *IISAnonPowerShell) Severity() string { return SeverityHigh }
func (r *IISAnonPowerShell) Evaluate(dir string) []Hit {
	return evalAnonExchangeEndpoint(dir, r.ID(), r.Name(), r.MITRE(), r.Severity(),
		func(stem string) bool { return strings.Contains(stem, "/powershell") },
		"anonymous request to the Exchange PowerShell back end")
}

// --- IIS-06: Anonymous access to the ECP admin surface from a remote client ---
type IISAnonECP struct{}

func (r *IISAnonECP) ID() string       { return "IIS-06" }
func (r *IISAnonECP) Name() string     { return "Anonymous Exchange ECP Access (ProxyLogon)" }
func (r *IISAnonECP) MITRE() string    { return "T1190" }
func (r *IISAnonECP) Severity() string { return SeverityNotable }
func (r *IISAnonECP) Evaluate(dir string) []Hit {
	return evalAnonExchangeEndpoint(dir, r.ID(), r.Name(), r.MITRE(), r.Severity(),
		func(stem string) bool { return strings.Contains(stem, "/ecp/") && !strings.Contains(stem, ".check") },
		"anonymous request to the Exchange ECP admin surface")
}

// evalAnonExchangeEndpoint is the shared body for IIS-05/06: flag anonymous
// requests to a sensitive Exchange endpoint (matched by stemMatch) from a remote
// (non-internal) client, aggregated per client IP. Anonymous internal traffic to
// these endpoints is normal (health probes, proxying) and is excluded.
func evalAnonExchangeEndpoint(dir, id, name, mitre, severity string, stemMatch func(string) bool, desc string) []Hit {
	type agg struct {
		count               int
		stems               map[string]bool
		firstTime, lastTime string
	}
	seen := map[string]*agg{}
	_ = csvutil.ReadCSVHelper(path.Join(dir, "iis", "iis_requests.csv"), func(header, row []string) error {
		stem := strings.ToLower(csvutil.SafeIndex(row, csvutil.GetColIndex(header, "uri_stem")))
		if !stemMatch(stem) {
			return nil
		}
		if !isAnonUser(csvutil.SafeIndex(row, csvutil.GetColIndex(header, "username"))) {
			return nil
		}
		client := csvutil.SafeIndex(row, csvutil.GetColIndex(header, "client_ip"))
		if exchangeInternalClient(client) {
			return nil
		}
		a := seen[client]
		if a == nil {
			a = &agg{stems: map[string]bool{}}
			seen[client] = a
		}
		a.count++
		a.stems[stem] = true
		updateWindow(&a.firstTime, &a.lastTime, csvutil.SafeIndex(row, csvutil.GetColIndex(header, "datetime_utc")))
		return nil
	})

	var hits []Hit
	for client, a := range seen {
		hits = append(hits, Hit{
			RuleID:         id,
			Severity:       severity,
			MITRE:          mitre,
			Title:          name,
			EvidenceSource: "iis/iis_requests.csv",
			EvidenceDetail: fmt.Sprintf("%s from %s: %d request(s) to [%s] between %s and %s",
				desc, client, a.count, joinSet(a.stems), a.firstTime, a.lastTime),
			TimelineSearchKey: client,
		})
	}
	sortHitsByKey(hits)
	return hits
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// updateWindow expands a [first,last] timestamp window with ts (RFC3339 strings
// sort lexically, so string comparison is chronological).
func updateWindow(first, last *string, ts string) {
	if ts == "" {
		return
	}
	if *first == "" || ts < *first {
		*first = ts
	}
	if ts > *last {
		*last = ts
	}
}

// uriBase returns the final path segment of a request URI stem (forward-slash
// separated), or "" if none. e.g. "/uploads/shell.aspx" -> "shell.aspx".
func uriBase(stem string) string {
	stem = strings.TrimRight(stem, "/")
	if stem == "" {
		return ""
	}
	if i := strings.LastIndex(stem, "/"); i >= 0 {
		return stem[i+1:]
	}
	return stem
}

// joinSet renders a set's keys as a sorted, comma-separated string for stable
// evidence output.
func joinSet(m map[string]bool) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// sortHitsByKey orders hits by their timeline search key so map-iteration order
// does not make the output non-deterministic between runs.
func sortHitsByKey(hits []Hit) {
	sort.Slice(hits, func(i, j int) bool { return hits[i].TimelineSearchKey < hits[j].TimelineSearchKey })
}

// --- IIS-07: Server script in an upload/temp directory ---
// A path-based heuristic that catches shells the content triage misses (obfuscated
// or DB-specific ones scoring no known tokens, e.g. an Mssql.aspx dropped in an
// upload folder): a server-executable script written into an upload or scratch
// directory is almost never legitimate — applications serve executable code from
// their app roots, not from user-upload or temp folders. Flags the whole stash
// regardless of file content, complementing the content-based IIS-01.
type IISUploadDirScript struct{}

func (r *IISUploadDirScript) ID() string       { return "IIS-07" }
func (r *IISUploadDirScript) Name() string     { return "Server Script in Upload/Temp Directory" }
func (r *IISUploadDirScript) MITRE() string    { return "T1505.003" }
func (r *IISUploadDirScript) Severity() string { return SeverityHigh }

// uploadDirSegments are path segments denoting an upload/scratch directory where
// an executable server script should never legitimately live.
var uploadDirSegments = []string{
	"foruploadfiles", "uploadfiles", "uploads", "upload",
	"temp", "tmp", "attachments", "userfiles", "fileupload",
}

func (r *IISUploadDirScript) Evaluate(dir string) []Hit {
	var hits []Hit
	_ = csvutil.ReadCSVHelper(path.Join(dir, "iis", "web_files.csv"), func(header, row []string) error {
		rel := csvutil.SafeIndex(row, csvutil.GetColIndex(header, "relative_path"))
		if rel == "" {
			return nil
		}
		lower := strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
		matched := ""
		for _, seg := range uploadDirSegments {
			if strings.Contains(lower, "/"+seg+"/") || strings.HasPrefix(lower, seg+"/") {
				matched = seg
				break
			}
		}
		if matched == "" {
			return nil
		}
		triage := csvutil.SafeIndex(row, csvutil.GetColIndex(header, "triage"))
		if triage == "" {
			triage = "INFO"
		}
		name := csvutil.SafeIndex(row, csvutil.GetColIndex(header, "filename"))
		if name == "" {
			name = rel
		}
		hits = append(hits, Hit{
			RuleID:            r.ID(),
			Severity:          r.Severity(),
			MITRE:             r.MITRE(),
			Title:             r.Name(),
			EvidenceSource:    "iis/web_files.csv",
			EvidenceDetail:    fmt.Sprintf("Server-executable script '%s' sits in an upload/scratch directory ('%s') where legitimate apps do not place code (content triage: %s). Classic web-shell drop location.", rel, matched, triage),
			TimelineSearchKey: name,
		})
		return nil
	})
	sortHitsByKey(hits)
	return hits
}
