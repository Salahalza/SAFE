package behavior

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Salahalza/SAFE/internal/csvutil"
)

// isExternalIP reports whether s is a routable public IP — i.e. not private
// (RFC1918), loopback, link-local, unspecified, or empty/"-". Logons and
// brute-force from such addresses on an internet-exposed host are the hostile ones.
func isExternalIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}

// jsonField pulls a scalar value for key out of an event_data JSON blob. The
// blob is already CSV-unescaped by the reader (real single quotes), so this
// handles both "key":"value" and "key":number without a full JSON parse.
func jsonField(data, key string) string {
	marker := `"` + key + `":`
	i := strings.Index(data, marker)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(data[i+len(marker):])
	if strings.HasPrefix(rest, `"`) {
		rest = rest[1:]
		if j := strings.Index(rest, `"`); j >= 0 {
			return rest[:j]
		}
		return ""
	}
	if j := strings.IndexAny(rest, ",}"); j >= 0 {
		return strings.TrimSpace(rest[:j])
	}
	return strings.TrimSpace(rest)
}

// --- LOGON-01: AuthBruteForce ---
// Aggregates failed logons (EventID 4625) and flags a brute-force / password-spray
// pattern — a burst of failures, especially from external source IPs against many
// accounts. Emits a single summary hit rather than thousands of rows.
type AuthBruteForce struct{}

func (r *AuthBruteForce) ID() string       { return "LOGON-01" }
func (r *AuthBruteForce) Name() string     { return "Authentication Brute Force / Password Spray" }
func (r *AuthBruteForce) MITRE() string    { return "T1110" }
func (r *AuthBruteForce) Severity() string { return SeverityHigh }

func (r *AuthBruteForce) Evaluate(dir string) []Hit {
	path := filepath.Join(dir, "evtx", "Security.csv")
	failByIP := map[string]int{}
	targets := map[string]bool{}
	total := 0
	_ = csvutil.ReadCSVHelper(path, func(header, row []string) error {
		idIdx := csvutil.GetColIndex(header, "event_id")
		dataIdx := csvutil.GetColIndex(header, "event_data")
		if idIdx == -1 || dataIdx == -1 || idIdx >= len(row) || dataIdx >= len(row) {
			return nil
		}
		if row[idIdx] != "4625" {
			return nil
		}
		total++
		if ip := jsonField(row[dataIdx], "IpAddress"); ip != "" && ip != "-" {
			failByIP[ip]++
		}
		if u := jsonField(row[dataIdx], "TargetUserName"); u != "" {
			targets[strings.ToLower(u)] = true
		}
		return nil
	})
	if total == 0 {
		return nil
	}

	const perIPThreshold = 20
	type ipCount struct {
		ip string
		n  int
	}
	var offenders []ipCount
	externalFails := 0
	for ip, n := range failByIP {
		if isExternalIP(ip) {
			externalFails += n
		}
		if n >= perIPThreshold {
			offenders = append(offenders, ipCount{ip, n})
		}
	}
	// Not enough to call it brute force.
	if len(offenders) == 0 && externalFails < 50 {
		return nil
	}
	sort.Slice(offenders, func(i, j int) bool { return offenders[i].n > offenders[j].n })

	var top []string
	hasExternal := false
	for _, o := range offenders {
		tag := ""
		if isExternalIP(o.ip) {
			tag = " [external]"
			hasExternal = true
		}
		if len(top) < 8 {
			top = append(top, fmt.Sprintf("%s(%d%s)", o.ip, o.n, tag))
		}
	}
	sev := SeverityNotable
	if hasExternal {
		sev = SeverityHigh
	}
	key := ""
	if len(offenders) > 0 {
		key = offenders[0].ip
	}
	return []Hit{{
		RuleID:            r.ID(),
		Severity:          sev,
		MITRE:             r.MITRE(),
		Title:             r.Name(),
		EvidenceSource:    "Security.csv",
		EvidenceDetail:    fmt.Sprintf("%d failed logons (EventID 4625) from %d source IP(s) against %d distinct account(s) — brute-force/spray. Top sources: %s", total, len(failByIP), len(targets), strings.Join(top, ", ")),
		TimelineSearchKey: key,
	}}
}

// --- LOGON-02: ExternalSuccessLogon ---
// Flags a SUCCESSFUL logon (EventID 4624) from an external/public IP — the moment
// an internet-facing host is actually breached. Privileged accounts are called out.
type ExternalSuccessLogon struct{}

func (r *ExternalSuccessLogon) ID() string       { return "LOGON-02" }
func (r *ExternalSuccessLogon) Name() string     { return "Successful Logon from External IP" }
func (r *ExternalSuccessLogon) MITRE() string    { return "T1078" }
func (r *ExternalSuccessLogon) Severity() string { return SeverityHigh }

func (r *ExternalSuccessLogon) Evaluate(dir string) []Hit {
	path := filepath.Join(dir, "evtx", "Security.csv")
	type key struct{ user, ip, ltype string }
	agg := map[key]int{}
	var order []key
	_ = csvutil.ReadCSVHelper(path, func(header, row []string) error {
		idIdx := csvutil.GetColIndex(header, "event_id")
		dataIdx := csvutil.GetColIndex(header, "event_data")
		if idIdx == -1 || dataIdx == -1 || idIdx >= len(row) || dataIdx >= len(row) {
			return nil
		}
		if row[idIdx] != "4624" {
			return nil
		}
		data := row[dataIdx]
		ip := jsonField(data, "IpAddress")
		if !isExternalIP(ip) {
			return nil
		}
		k := key{jsonField(data, "TargetUserName"), ip, jsonField(data, "LogonType")}
		if _, ok := agg[k]; !ok {
			order = append(order, k)
		}
		agg[k]++
		return nil
	})

	var hits []Hit
	for _, k := range order {
		priv := ""
		if lu := strings.ToLower(k.user); strings.Contains(lu, "admin") {
			priv = " (PRIVILEGED account)"
		}
		hits = append(hits, Hit{
			RuleID:            r.ID(),
			Severity:          SeverityHigh,
			MITRE:             r.MITRE(),
			Title:             r.Name(),
			EvidenceSource:    "Security.csv",
			EvidenceDetail:    fmt.Sprintf("Account '%s'%s logged on successfully (EventID 4624, LogonType %s) from EXTERNAL IP %s — %d time(s).", k.user, priv, k.ltype, k.ip, agg[k]),
			TimelineSearchKey: k.ip,
		})
	}
	return hits
}
