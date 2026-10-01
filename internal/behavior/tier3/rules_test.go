package tier3

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"

	"github.com/Salahalza/SAFE/internal/behavior"
)

var timelineHeader = []string{
	"datetime", "timezone", "MACB", "source", "sourcetype", "type", "user",
	"host", "short", "desc", "version", "filename", "inode", "notes", "format", "extra",
}

func evRow(datetime, typ, short, desc string) []string {
	return []string{datetime, "UTC", "....", "EventLog", "Security", typ, "", "HOST", short, desc, "2", "", "", "", "safe", ""}
}

func writeTimeline(t *testing.T, rows [][]string) string {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "timeline.csv"))
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	_ = w.Write(timelineHeader)
	for _, r := range rows {
		_ = w.Write(r)
	}
	w.Flush()
	f.Close()
	return dir
}

// TestT3_03FiresOnLogon3ThenService proves T3-03 correlates a 4624 Type-3
// network logon with a service creation (7045) inside the window — the real
// timeline conventions the rule now keys off — and does not fire when the
// service creation falls outside the window.
func TestT3_03FiresOnLogon3ThenService(t *testing.T) {
	logon := `Provider: Microsoft-Windows-Security-Auditing, EventData: {"LogonType":3,"IpAddress":"10.0.0.9"}`
	svc := `Provider: Service Control Manager, EventData: {"ServiceName":"EvilSvc","ImagePath":"C:\Windows\Temp\evil.exe"}`
	dir := writeTimeline(t, [][]string{
		evRow("2026-01-01 10:00:00.000000", "EventID: 4624", "logon", logon),
		evRow("2026-01-01 10:00:30.000000", "EventID: 7045", "New Service: EvilSvc", svc),
	})

	hits, err := RunEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := countRule(hits, "T3-03")
	if n != 1 {
		t.Fatalf("T3-03 fired %d times, want 1: %+v", n, hits)
	}
}

// TestT3_03NoFireOnBenignService is the clean-DC false-positive case: a network
// logon followed by a legitimate driver/application service install (Program
// Files / System32) must NOT fire, even inside the window.
func TestT3_03NoFireOnBenignService(t *testing.T) {
	logon := `Provider: X, EventData: {"LogonType":3,"IpAddress":"10.0.0.9"}`
	benign := `Provider: Service Control Manager, EventData: {"ServiceName":"Edge","ImagePath":"\"C:\Program Files (x86)\Microsoft\Edge\elevation_service.exe\""}`
	driver := `Provider: Service Control Manager, EventData: {"ServiceName":"NIC","ImagePath":"\SystemRoot\System32\drivers\e1i68x64.sys"}`
	dir := writeTimeline(t, [][]string{
		evRow("2026-01-01 10:00:00.000000", "EventID: 4624", "logon", logon),
		evRow("2026-01-01 10:00:20.000000", "EventID: 7045", "Edge", benign),
		evRow("2026-01-01 10:00:40.000000", "EventID: 7045", "NIC", driver),
	})
	hits, err := RunEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := countRule(hits, "T3-03"); n != 0 {
		t.Fatalf("T3-03 fired %d times on benign service installs, want 0", n)
	}
}

// TestT3_03NoFireOutsideWindow confirms the 2-minute window is enforced.
func TestT3_03NoFireOutsideWindow(t *testing.T) {
	logon := `Provider: X, EventData: {"LogonType":3,"IpAddress":"10.0.0.9"}`
	svc := `Provider: SCM, EventData: {"ImagePath":"C:\Windows\Temp\evil.exe"}`
	dir := writeTimeline(t, [][]string{
		evRow("2026-01-01 10:00:00.000000", "EventID: 4624", "logon", logon),
		evRow("2026-01-01 10:10:00.000000", "EventID: 7045", "svc", svc),
	})
	hits, err := RunEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := countRule(hits, "T3-03"); n != 0 {
		t.Fatalf("T3-03 fired %d times outside the window, want 0", n)
	}
}

// TestT3_03IgnoresNonType3 confirms a non-Type-3 logon does not arm the rule.
func TestT3_03IgnoresNonType3(t *testing.T) {
	logon := `Provider: X, EventData: {"LogonType":2,"IpAddress":"-"}`
	svc := `Provider: SCM, EventData: {"ImagePath":"C:\Windows\Temp\evil.exe"}`
	dir := writeTimeline(t, [][]string{
		evRow("2026-01-01 10:00:00.000000", "EventID: 4624", "logon", logon),
		evRow("2026-01-01 10:00:30.000000", "EventID: 7045", "svc", svc),
	})
	hits, err := RunEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := countRule(hits, "T3-03"); n != 0 {
		t.Fatalf("T3-03 fired %d times on a Type-2 logon, want 0", n)
	}
}

func countRule(hits []behavior.Hit, id string) int {
	n := 0
	for _, h := range hits {
		if h.RuleID == id {
			n++
		}
	}
	return n
}
