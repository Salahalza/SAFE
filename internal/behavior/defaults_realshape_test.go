package behavior

import (
	"path/filepath"
	"testing"
)

// TestDefaultRulesAgainstRealEventShapes drives the embedded default rules over
// evidence shaped exactly like SAFE's evtx parser actually emits it, rather than
// the minimal stand-ins in TestDefaultRuleMatching. The event_data values are
// real JSON as the parser writes it (full Security-4688/4624/4720 and Defender
// field sets), and the CSVs carry the real 7-column header
// (time_created_utc,event_id,provider,channel,computer,level,event_data). The
// engine resolves columns by header name, so the extra columns must not matter —
// this proves it, and proves each rule's literal (e.g. `"LogonType":10` as a bare
// int, `"TokenElevationType":"%%1937"` as a quoted string) matches the parser's
// real output, not a hand-simplified guess.
//
// Motivated by what a real Domain Controller case (CASE-SAFE-FULLCASE-DCVM)
// actually contained: B-05 (via a real 5001) and B-07 (24 real 4720s) fire on
// that evidence, but B-06/T2-11/T2-12 could not — the capture had only
// TokenElevationType %%1936 (Type 1, not the %%1937 full elevation B-06 wants),
// no 1102/104 log-clear, and 4688 CommandLine captured but EMPTY (the audit GPO
// for command-line inclusion was off). So the positive cases those three rules
// need are reproduced here at full fidelity, alongside the real benign shapes
// that must stay excluded.
func TestDefaultRulesAgainstRealEventShapes(t *testing.T) {
	dir := t.TempDir()

	realHeader := []string{"time_created_utc", "event_id", "provider", "channel", "computer", "level", "event_data"}
	// sec builds a Security.csv row with the real header shape.
	sec := func(id, data string) []string {
		return []string{"2026-07-04T00:36:55.7Z", id, "Microsoft-Windows-Security-Auditing", "Security", "WIN-DC01", "0", data}
	}

	writeCSV(t, filepath.Join(dir, "evtx", "Security.csv"), realHeader, [][]string{
		// B-06: full-elevation token (Type 2 = %%1937) fires; the default
		// Type 1 (%%1936), which is all the real DC had, must not.
		sec("4688", `{"SubjectUserName":"admin","SubjectDomainName":"SAFE","SubjectLogonId":181234,"NewProcessId":4444,"NewProcessName":"C:\\Windows\\System32\\cmd.exe","TokenElevationType":"%%1937","ProcessId":2600,"CommandLine":"","ParentProcessName":"C:\\Windows\\explorer.exe","MandatoryLabel":"S-1-16-12288"}`),
		sec("4688", `{"SubjectUserName":"SYSTEM","SubjectDomainName":"NT AUTHORITY","SubjectLogonId":999,"NewProcessId":100,"NewProcessName":"Registry","TokenElevationType":"%%1936","ProcessId":4,"CommandLine":"","ParentProcessName":"","MandatoryLabel":"S-1-16-16384"}`),

		// T2-12: real anti-forensics wipes every shadow (/all) and now carries a
		// populated CommandLine — fires. The two forms that must NOT fire: SAFE's
		// own targeted /shadow={GUID} cleanup, and the real-DC empty CommandLine.
		// %%1936 here (not %%1937) keeps this row isolated to T2-12 — the B-06
		// elevation case is tested by the cmd.exe row above.
		sec("4688", `{"SubjectUserName":"attacker","NewProcessName":"C:\\Windows\\System32\\vssadmin.exe","TokenElevationType":"%%1936","CommandLine":"vssadmin  delete shadows /all /quiet","ParentProcessName":"C:\\Windows\\System32\\cmd.exe"}`),
		sec("4688", `{"SubjectUserName":"SYSTEM","NewProcessName":"C:\\Windows\\System32\\vssadmin.exe","TokenElevationType":"%%1936","CommandLine":"vssadmin delete shadows /shadow={b3f2a1c0-0000-0000-0000-000000000000} /quiet","ParentProcessName":""}`),
		sec("4688", `{"SubjectUserName":"svc","NewProcessName":"C:\\Windows\\System32\\svchost.exe","TokenElevationType":"%%1936","CommandLine":"","ParentProcessName":""}`),

		// B-07: local/account creation. 4720 fires regardless of the rest.
		sec("4720", `{"TargetUserName":"backdoor","TargetDomainName":"WIN-DC01","TargetSid":"S-1-5-21-1-2-3-1105","SubjectUserName":"Administrator","SubjectDomainName":"SAFE","PrivilegeList":"-","SamAccountName":"backdoor"}`),

		// B-08: remote interactive (RDP) logon. External IP fires; loopback and a
		// non-RDP logon type must not.
		sec("4624", `{"TargetUserName":"admin","TargetDomainName":"SAFE","LogonType":10,"IpAddress":"203.0.113.9","IpPort":"51920","LogonProcessName":"User32","AuthenticationPackageName":"Negotiate","WorkstationName":"KALI"}`),
		sec("4624", `{"TargetUserName":"admin","LogonType":10,"IpAddress":"127.0.0.1","IpPort":"0"}`),
		sec("4624", `{"TargetUserName":"SYSTEM","TargetDomainName":"NT AUTHORITY","LogonType":0,"IpAddress":"-","IpPort":"-"}`),

		// T2-11: Security log cleared (1102).
		sec("1102", `{"SubjectUserName":"attacker","SubjectDomainName":"SAFE","SubjectLogonId":"0x3e7"}`),
	})

	// B-05: Defender channel (matched by the *Defender* glob). 5001 always fires;
	// a 5007 naming a protection-disabling value fires (contains is
	// case-insensitive, so the real mixed-case "DisableRealtimeMonitoring"
	// matches the rule's lowercase key); the real benign InstallLocation 5007 —
	// 227 of which the DC produced — must stay excluded.
	defHeader := realHeader
	def := func(id, data string) []string {
		return []string{"2026-07-04T00:37:02.8Z", id, "Microsoft-Windows-Windows Defender", "Microsoft-Windows-Windows Defender/Operational", "WIN-DC01", "4", data}
	}
	writeCSV(t, filepath.Join(dir, "evtx", "Microsoft-Windows-Windows-Defender-Operational.csv"), defHeader, [][]string{
		def("5001", `{"Product Name":"Microsoft Defender Antivirus","Product Version":"4.18.2104.5","Feature Name":"Real-Time Protection"}`),
		def("5007", `{"Product Name":"Microsoft Defender Antivirus","Old Value":"0x0","New Value":"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1"}`),
		def("5007", `{"Product Name":"Microsoft Defender Antivirus","Old Value":"Default\\InstallLocation = C:\\Program Files\\Windows Defender","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\InstallLocation = C:\\Program Files\\Windows Defender\\"}`),
	})

	hits, err := Run(dir, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := map[string]int{}
	for _, h := range hits {
		got[h.RuleID]++
	}

	want := map[string]int{
		"B-05":  2, // 5001 + the DisableRealtimeMonitoring 5007; InstallLocation 5007 excluded
		"B-06":  1, // %%1937 fires; %%1936 excluded
		"B-07":  1, // 4720
		"B-08":  1, // external RDP; loopback + non-RDP excluded
		"T2-11": 1, // 1102
		"T2-12": 1, // /all fires; targeted /shadow= and empty CommandLine excluded
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("rule %s: expected %d hits on real-shape evidence, got %d", id, n, got[id])
		}
	}
}
