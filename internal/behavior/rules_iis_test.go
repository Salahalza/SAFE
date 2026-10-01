package behavior

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExchangeProxyRules exercises the ProxyLogon/ProxyShell rules (IIS-04/05/06)
// with crafted request rows: malicious lines that must fire, and benign lines
// (loopback/empty-client anon traffic, authenticated access, and a legitimate
// AutoDiscover V2 autodiscover.json request) that must not — the exact shapes a
// real clean Exchange server produces in bulk.
func TestExchangeProxyRules(t *testing.T) {
	dir := t.TempDir()
	iisDir := filepath.Join(dir, "iis")
	if err := os.MkdirAll(iisDir, 0o755); err != nil {
		t.Fatal(err)
	}

	header := "datetime_utc,site,server_ip,server_port,method,uri_stem,uri_query,protocol_status,substatus,win32_status,bytes_sent,bytes_received,time_taken_ms,client_ip,username,user_agent,referer,host,source_log"
	rows := []string{
		header,
		// --- benign: must NOT fire ---
		"2026-07-08T00:00:01Z,,10.0.0.5,443,POST,/powershell,,200,0,0,,,5,::1,,UA,,,u.log",                                    // anon PowerShell from loopback (health probe)
		"2026-07-08T00:00:02Z,,10.0.0.5,443,POST,/powershell,,200,0,0,,,5,,,UA,,,u.log",                                       // anon PowerShell, empty client (proxied)
		"2026-07-08T00:00:03Z,,10.0.0.5,443,POST,/powershell,,200,0,0,,,5,45.66.77.88,SAFE\\admin,UA,,,u.log",                 // authenticated remote PowerShell
		"2026-07-08T00:00:04Z,,10.0.0.5,443,GET,/autodiscover/autodiscover.json,Email=user@example.com&Protocol=ActiveSync,200,0,0,,,5,45.66.77.88,,UA,,,u.log", // legit AutoDiscover V2 (no backend token)
		"2026-07-08T00:00:05Z,,10.0.0.5,443,POST,/ecp/exhealth.check,,200,0,0,,,5,45.66.77.88,,UA,,,u.log",                    // ecp health check (excluded)
		// --- malicious: must fire ---
		"2026-07-08T00:01:00Z,,10.0.0.5,443,POST,/autodiscover/autodiscover.json,@example.com/powershell/?X-Rps-CAT=abc,200,0,0,,,5,45.66.77.88,,UA,,,u.log", // IIS-04 SSRF -> powershell backend
		"2026-07-08T00:02:00Z,,10.0.0.5,443,POST,/powershell,,200,0,0,,,5,45.66.77.88,,UA,,,u.log",                            // IIS-05 anon PowerShell from remote
		"2026-07-08T00:03:00Z,,10.0.0.5,443,POST,/ecp/DDI/DDIService.svc,,200,0,0,,,5,45.66.77.88,,UA,,,u.log",               // IIS-06 anon ECP from remote
	}
	content := ""
	for _, r := range rows {
		content += r + "\n"
	}
	if err := os.WriteFile(filepath.Join(iisDir, "iis_requests.csv"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	check := func(rule Rule, want int) {
		t.Helper()
		got := len(rule.Evaluate(dir))
		if got != want {
			t.Errorf("%s (%s): expected %d hit(s), got %d", rule.ID(), rule.Name(), want, got)
		}
	}
	check(&IISProxyShellSSRF{}, 1)
	check(&IISAnonPowerShell{}, 1)
	check(&IISAnonECP{}, 1)
}
