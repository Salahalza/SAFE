package analyzer

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Salahalza/SAFE/internal/evidence"
)

// webScriptExts is the set of server-executable script extensions the web-file
// scan inspects. A web shell is almost always one of these dropped into a site
// root; static assets (.html/.js/.css/.png) are not server-executed and are not
// scanned. Comparison is case-insensitive.
var webScriptExts = map[string]bool{
	".aspx": true, ".asmx": true, ".ashx": true, ".asax": true,
	".ascx": true, ".cshtml": true, ".asp": true,
	".php": true, ".php3": true, ".php4": true, ".php5": true, ".phtml": true,
	".jsp": true, ".jspx": true, ".pl": true, ".cgi": true,
}

// strongShellTokens are high-confidence web-shell indicators — process
// execution, in-memory assembly loading, or database command shells that have
// almost no place in a normal page. A single strong token is enough to triage a
// file HIGH. Tokens are matched case-insensitively as substrings.
var strongShellTokens = []string{
	"xp_cmdshell",
	"system.diagnostics.process",
	"processstartinfo",
	"wscript.shell",
	"shell_exec(",
	"passthru(",
	"proc_open(",
	"popen(",
	"frombase64string",
	"runtime.getruntime().exec",
	"processbuilder",
	"[reflection.assembly]",
	"cmd.exe /c",
	"cmd /c ",
	"powershell -",
	"server.createobject(\"wscript",
}

// weakShellTokens individually appear in a great deal of legitimate code — in
// particular `eval(` matches ASP.NET's ubiquitous `DataBinder.Eval` /
// `<%# Eval(...) %>` data binding, and `request.querystring` is normal in any
// page that reads a parameter. So a single weak token is NOT flagged at all
// (INFO); two or more together (INFO) start to look like the dynamic-evaluation
// + untrusted-input pairing a shell chains, which is NOTABLE. Validated against
// a real Exchange server's 700+ shipped OWA/ECP scripts, which each carry at
// most one such token and must not be flagged.
var weakShellTokens = []string{
	"eval(",
	"assert(",
	"base64_decode(",
	"create_function(",
	"execute(",
	"executeglobal",
	"request.form",
	"request.querystring",
	"request.item",
	"$_post",
	"$_get",
	"$_request",
	"gzinflate(",
	"str_rot13(",
}

// scanWebFiles reads the collected server-script files from the iis_collection
// output — the per-module encrypted payload container (evidence.ContainerName),
// or a legacy loose web/ tree for cases collected before the container migration —
// hashes each file, scans its content for web-shell indicators, and writes
// web_files.csv with a triage tier per file. Returns the output path ("" when no
// web files were collected), the file count, and how many were flagged above INFO.
//
// Scanning file content for attacker tokens is lab-side detection, squarely
// within the defensive charter — the same posture as an EDR or AV signature
// engine. The collector on the target only copied raw bytes.
func (p *IISLogParser) scanWebFiles(root, outDir string) (string, int, int, []error) {
	type record struct {
		rel, name, ext, size, sha, triage, strong, weak, inds string
	}
	var records []record
	var errs []error
	flagged := 0

	// build assembles one record from a collected web script's case-relative path
	// (forward-slash separated) and its raw content. Non-script extensions are
	// skipped (ok=false). The reported name, size, SHA-256 and triage all reflect
	// the true, unmodified file.
	build := func(relPath string, content []byte) (record, bool) {
		ext := strings.ToLower(filepath.Ext(relPath))
		if !webScriptExts[ext] {
			return record{}, false
		}
		sum := sha256.Sum256(content)
		strong, weak := scanShellIndicatorsBytes(content)
		triage := triageWebFile(len(strong), len(weak))
		if triage != "INFO" {
			flagged++
		}
		return record{
			rel:    relPath,
			name:   path.Base(relPath),
			ext:    ext,
			size:   fmt.Sprintf("%d", len(content)),
			sha:    hex.EncodeToString(sum[:]),
			triage: triage,
			strong: fmt.Sprintf("%d", len(strong)),
			weak:   fmt.Sprintf("%d", len(weak)),
			inds:   strings.Join(append(append([]string{}, strong...), weak...), "|"),
		}, true
	}

	containerPath := filepath.Join(root, evidence.ContainerName)
	if evidence.ContainerExists(containerPath) {
		// Current format: raw, unmodified payloads inside the per-module encrypted
		// container. Entry names are the case-relative paths ("<siteID>/<rel>").
		if rerr := evidence.ReadContainer(containerPath, func(name string, data []byte) error {
			if rec, ok := build(filepath.ToSlash(name), data); ok {
				records = append(records, rec)
			}
			return nil
		}); rerr != nil {
			errs = append(errs, fmt.Errorf("read payload container: %w", rerr))
		}
	} else {
		// Legacy format: a loose web/ tree of raw or .qtn-transformed files, from a
		// case collected before the container migration. Recover the original name
		// and decode any .qtn content before hashing and scanning.
		webRoot := filepath.Join(root, "web")
		if info, err := os.Stat(webRoot); err != nil || !info.IsDir() {
			return "", 0, 0, nil // nothing collected
		}
		if err := filepath.Walk(webRoot, func(fp string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() || !info.Mode().IsRegular() {
				return nil
			}
			storedName := info.Name()
			if !webScriptExts[strings.ToLower(filepath.Ext(evidence.OriginalName(storedName)))] {
				return nil
			}
			content, rerr := readWebFileContent(fp, storedName)
			if rerr != nil {
				errs = append(errs, fmt.Errorf("read %s: %w", evidence.OriginalName(storedName), rerr))
				return nil
			}
			rel, _ := filepath.Rel(webRoot, fp)
			if rec, ok := build(evidence.OriginalName(filepath.ToSlash(rel)), content); ok {
				records = append(records, rec)
			}
			return nil
		}); err != nil {
			errs = append(errs, fmt.Errorf("walk web files: %w", err))
		}
	}

	if len(records) == 0 {
		return "", 0, 0, errs
	}

	csvPath := filepath.Join(outDir, "web_files.csv")
	f, cerr := os.Create(csvPath)
	if cerr != nil {
		return "", 0, 0, append(errs, fmt.Errorf("create web_files.csv: %w", cerr))
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if werr := w.Write([]string{
		"relative_path", "filename", "extension", "size_bytes", "sha256",
		"triage", "strong_indicators", "weak_indicators", "indicators",
	}); werr != nil {
		return "", 0, 0, append(errs, fmt.Errorf("write header: %w", werr))
	}
	for _, r := range records {
		if werr := w.Write([]string{
			csvSafe(r.rel), csvSafe(r.name), r.ext, r.size, r.sha,
			r.triage, r.strong, r.weak, csvSafe(r.inds),
		}); werr != nil {
			errs = append(errs, fmt.Errorf("write row %s: %w", r.name, werr))
		}
	}

	return csvPath, len(records), flagged, errs
}

// readWebFileContent reads a collected web-root script, decoding the
// quarantine-safe transform when the stored file carries evidence.EncodedSuffix
// (so a host AV could not quarantine the shell on write). A file without the
// marker — e.g. from an older case — is returned as-is, keeping backward
// compatibility.
func readWebFileContent(path, storedName string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if evidence.IsEncoded(storedName) {
		evidence.Transform(data, 0) // symmetric: decodes
	}
	return data, nil
}

// scanShellIndicatorsBytes returns the distinct strong and weak web-shell tokens
// in a file's content. Only the first 1 MiB is inspected — that covers real
// shells (which are small) while bounding work on a large legitimate file.
func scanShellIndicatorsBytes(content []byte) (strong, weak []string) {
	if len(content) > 1<<20 {
		content = content[:1<<20]
	}
	lc := strings.ToLower(string(content))
	for _, tok := range strongShellTokens {
		if strings.Contains(lc, tok) {
			strong = append(strong, tok)
		}
	}
	for _, tok := range weakShellTokens {
		if strings.Contains(lc, tok) {
			weak = append(weak, tok)
		}
	}
	return strong, weak
}

// triageWebFile maps indicator counts to a triage tier the behavioral web-shell
// rule trusts directly (mirroring how the scheduled-tasks and COM-hijack parsers
// pre-tier their rows). A single strong token (process execution, in-memory
// assembly loading, DB command shell) is HIGH on its own; two or more weak
// tokens together are NOTABLE; a lone weak token is INFO, because real evidence
// (a clean Exchange server's shipped OWA/ECP pages) showed single weak tokens
// like `eval(`/`request.querystring` are pervasive in legitimate framework code
// and flagging them buries true positives in noise.
func triageWebFile(strong, weak int) string {
	switch {
	case strong >= 1:
		return "HIGH"
	case weak >= 2:
		return "NOTABLE"
	default:
		return "INFO"
	}
}
