package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Salahalza/SAFE/internal/analyzer/timeline"
	"github.com/Salahalza/SAFE/internal/behavior"
	"github.com/Salahalza/SAFE/internal/csvutil"
	"github.com/Salahalza/SAFE/internal/evidence"
)

// buildSyntheticIISCase lays out a case folder that mirrors what the
// iis_collection module produces (a *_iis_collection module dir holding the
// config, a logs/ tree of W3C files, and a web/ tree of collected scripts), so
// the parser and the IIS behavioral rules can be exercised end-to-end without a
// live IIS host.
func buildSyntheticIISCase(t *testing.T) string {
	t.Helper()
	caseDir := t.TempDir()
	mod := filepath.Join(caseDir, "modules", "00_iis_collection")

	logDir := filepath.Join(mod, "logs", "W3SVC1")
	webDir := filepath.Join(mod, "web", "1", "uploads")
	for _, d := range []string{logDir, webDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	log := "#Software: Microsoft Internet Information Services 10.0\n" +
		"#Version: 1.0\n" +
		"#Date: 2026-07-08 00:00:00\n" +
		"#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n" +
		"2026-07-08 00:01:02 10.0.0.5 GET /default.aspx - 80 - 192.168.1.10 Mozilla/5.0 - 200 0 0 15\n" +
		"2026-07-08 00:02:03 10.0.0.5 POST /uploads/shell.aspx cmd=whoami 80 - 45.66.77.88 curl/7.68 - 200 0 0 40\n" +
		"2026-07-08 00:03:04 10.0.0.5 GET /uploads/shell.aspx - 80 - 45.66.77.88 Mozilla/5.0 - 200 0 0 20\n"
	writeFile(t, filepath.Join(logDir, "u_ex260708.log"), log)

	// A malicious script: process execution + untrusted input = strong+weak -> HIGH.
	shell := `<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request.QueryString["cmd"]); %>`
	writeFile(t, filepath.Join(mod, "web", "1", "uploads", "shell.aspx"), shell)
	// A benign page: no indicators -> INFO.
	writeFile(t, filepath.Join(mod, "web", "1", "default.aspx"), "<html>Hello</html>")
	// The collected config, present but irrelevant to these assertions.
	writeFile(t, filepath.Join(mod, "applicationHost.config"), "<configuration/>")

	return caseDir
}

// TestIISWebFilesFromContainer exercises the current storage form: web-root
// scripts are stored raw inside a per-module ZipCrypto-encrypted container
// (evidence.ContainerName), not as loose files. It confirms the analyzer reads the
// container, triages the same way as the loose-tree path, and that the stored
// bytes are recovered byte-for-byte (architectural principle #9).
func TestIISWebFilesFromContainer(t *testing.T) {
	caseDir := t.TempDir()
	mod := filepath.Join(caseDir, "modules", "00_iis_collection")
	if err := os.MkdirAll(mod, 0o755); err != nil {
		t.Fatalf("mkdir mod: %v", err)
	}

	shell := `<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request.QueryString["cmd"]); %>`
	benign := "<html>Hello</html>"

	cw, err := evidence.NewContainerWriter(filepath.Join(mod, evidence.ContainerName))
	if err != nil {
		t.Fatalf("container writer: %v", err)
	}
	if err := cw.Add("1/uploads/shell.aspx", []byte(shell)); err != nil {
		t.Fatalf("add shell: %v", err)
	}
	if err := cw.Add("1/default.aspx", []byte(benign)); err != nil {
		t.Fatalf("add benign: %v", err)
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("close container: %v", err)
	}

	labReportDir := filepath.Join(caseDir, "lab_report")
	_, stats, errs := (&IISLogParser{}).Parse(caseDir, labReportDir, nil)
	if len(errs) > 0 {
		t.Fatalf("parser errors: %v", errs)
	}
	if stats["web_files"] != 2 {
		t.Errorf("expected 2 web files, got %d", stats["web_files"])
	}
	if stats["web_files_flagged"] != 1 {
		t.Errorf("expected 1 flagged web file, got %d", stats["web_files_flagged"])
	}

	triage := map[string]string{}
	_ = csvutil.ReadCSVHelper(filepath.Join(labReportDir, "iis", "web_files.csv"), func(h, row []string) error {
		triage[row[csvutil.GetColIndex(h, "filename")]] = row[csvutil.GetColIndex(h, "triage")]
		return nil
	})
	if triage["shell.aspx"] != "HIGH" {
		t.Errorf("shell.aspx: expected HIGH, got %q", triage["shell.aspx"])
	}
	if triage["default.aspx"] != "INFO" {
		t.Errorf("default.aspx: expected INFO, got %q", triage["default.aspx"])
	}

	// Byte-for-byte recovery from the container (principle #9 requirement (a)).
	got, err := evidence.ReadContainerEntry(filepath.Join(mod, evidence.ContainerName), "1/uploads/shell.aspx")
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	if string(got) != shell {
		t.Errorf("container round-trip mismatch:\n got: %q\nwant: %q", string(got), shell)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestIISParserAndRules(t *testing.T) {
	caseDir := buildSyntheticIISCase(t)
	labReportDir := filepath.Join(caseDir, "lab_report")

	outputs, stats, errs := (&IISLogParser{}).Parse(caseDir, labReportDir, nil)
	if len(errs) > 0 {
		t.Fatalf("parser errors: %v", errs)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected 2 outputs (requests + web_files), got %d: %v", len(outputs), outputs)
	}
	if stats["requests"] != 3 {
		t.Errorf("expected 3 request rows, got %d", stats["requests"])
	}
	if stats["web_files"] != 2 {
		t.Errorf("expected 2 web files, got %d", stats["web_files"])
	}
	if stats["web_files_flagged"] != 1 {
		t.Errorf("expected 1 flagged web file, got %d", stats["web_files_flagged"])
	}

	// Confirm shell.aspx triaged HIGH and default.aspx INFO in web_files.csv.
	triage := map[string]string{}
	_ = csvutil.ReadCSVHelper(filepath.Join(labReportDir, "iis", "web_files.csv"), func(h, row []string) error {
		n := csvutil.GetColIndex(h, "filename")
		tr := csvutil.GetColIndex(h, "triage")
		triage[row[n]] = row[tr]
		return nil
	})
	if triage["shell.aspx"] != "HIGH" {
		t.Errorf("shell.aspx: expected HIGH, got %q", triage["shell.aspx"])
	}
	if triage["default.aspx"] != "INFO" {
		t.Errorf("default.aspx: expected INFO, got %q", triage["default.aspx"])
	}

	// Confirm datetime normalization produced RFC3339 in iis_requests.csv.
	var firstDT string
	_ = csvutil.ReadCSVHelper(filepath.Join(labReportDir, "iis", "iis_requests.csv"), func(h, row []string) error {
		if firstDT == "" {
			firstDT = row[csvutil.GetColIndex(h, "datetime_utc")]
		}
		return nil
	})
	if firstDT != "2026-07-08T00:01:02Z" {
		t.Errorf("datetime normalization: expected 2026-07-08T00:01:02Z, got %q", firstDT)
	}

	// Run the behavioral engine and confirm the IIS rules fired.
	hits, err := behavior.Run(labReportDir, "")
	if err != nil {
		t.Fatalf("behavior.Run: %v", err)
	}
	got := map[string]int{}
	for _, h := range hits {
		got[h.RuleID]++
	}
	if got["IIS-01"] != 1 {
		t.Errorf("IIS-01 (web-shell file): expected 1 hit, got %d", got["IIS-01"])
	}
	if got["IIS-02"] != 1 {
		t.Errorf("IIS-02 (web-shell accessed): expected 1 hit, got %d", got["IIS-02"])
	}
	if got["IIS-03"] != 1 {
		t.Errorf("IIS-03 (LOLBin in request): expected 1 hit, got %d", got["IIS-03"])
	}

	// Confirm the supertimeline injects the two requests that reached the flagged
	// shell (the GET and POST to /uploads/shell.aspx) at their real timestamps.
	if _, err := timeline.Generate(labReportDir); err != nil {
		t.Fatalf("timeline.Generate: %v", err)
	}
	shellAccessRows := 0
	_ = csvutil.ReadCSVHelper(filepath.Join(labReportDir, "timeline.csv"), func(h, row []string) error {
		if row[csvutil.GetColIndex(h, "sourcetype")] == "WebShellAccess" {
			shellAccessRows++
		}
		return nil
	})
	if shellAccessRows != 2 {
		t.Errorf("timeline WebShellAccess rows: expected 2, got %d", shellAccessRows)
	}
}
