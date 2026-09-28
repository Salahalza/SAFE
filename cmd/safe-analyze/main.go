package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/analyzer"
	"github.com/Salahalza/SAFE/internal/analyzer/timeline"
	"github.com/Salahalza/SAFE/internal/behavior"
	"github.com/Salahalza/SAFE/internal/behavior/tier3"
	"github.com/Salahalza/SAFE/internal/engine"
	"github.com/Salahalza/SAFE/internal/evidence"
	"github.com/Salahalza/SAFE/internal/ioc"
	"github.com/Salahalza/SAFE/internal/html_report"
	"github.com/Salahalza/SAFE/internal/manifest"
	"github.com/Salahalza/SAFE/internal/tui_analyze"
)

// runDecode recovers the original content of a collected payload. It handles both
// storage forms:
//
//   - A per-case encrypted payload container (evidence.ContainerName): with -entry
//     it extracts that one raw entry; without -entry it lists the container's
//     entries so the analyst can pick one. (Any third-party tool — 7-Zip, unzip —
//     can also extract it with the documented password.)
//   - A legacy loose file: a .qtn-marked file is transform-decoded; any other file
//     is passed through unchanged.
//
// Output goes to stdout by default so a decoded web shell is never written back to
// disk (where the host AV would quarantine it) — the analyst pipes it to a pager
// or grep. An explicit -out path writes the decoded bytes to disk if wanted.
func runDecode(path, entry, out string) error {
	base := filepath.Base(path)
	isContainer := entry != "" || base == evidence.ContainerName

	if isContainer {
		if entry == "" {
			fmt.Fprintf(os.Stderr, "Payload container %s. Entries:\n", path)
			if err := evidence.ReadContainer(path, func(name string, _ []byte) error {
				fmt.Fprintf(os.Stderr, "  %s\n", name)
				return nil
			}); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "\nRe-run with -entry <name> to decode one.")
			return nil
		}
		data, err := evidence.ReadContainerEntry(path, entry)
		if err != nil {
			return fmt.Errorf("entry %q: %w", entry, err)
		}
		return emitDecoded(data, out, path+"!"+entry)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if evidence.IsEncoded(base) {
		evidence.Transform(data, 0)
	}
	return emitDecoded(data, out, path)
}

// emitDecoded writes recovered bytes to stdout (default) or to an explicit path.
func emitDecoded(data []byte, out, label string) error {
	if out == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Decoded %s -> %s\n", label, out)
	return nil
}


func main() {
	var (
		verifyDir   = flag.String("verify", "", "Verify integrity of a case folder. Specify the case folder path.")
		analyzeDir  = flag.String("analyze", "", "Run analyzer parsers against a collected case folder. Specify the case folder path.")
		tuiMode     = flag.Bool("tui", false, "Launch the interactive TUI report viewer.")
		extractIocs = flag.String("extract-iocs", "", "Extract IOCs from a PDF or text threat report. Specify the file path.")
		reportDate  = flag.String("report-date", "", "Publication date of the threat report (YYYY-MM-DD). Sets STIX valid_from. Defaults to today if omitted.")
		serveDir    = flag.String("serve", "", "Start a local web server to view the case report. Specify the case folder path.")
		servePort   = flag.Int("port", 8080, "Port for the local web server.")
		decodeFile  = flag.String("decode", "", "Recover a collected payload's original content to stdout. Point at a payload container (web_payloads.zip) and pass -entry <name> to extract one shell (omit -entry to list entries), or at a legacy .qtn file. Pipe to a pager so the malware is not re-materialized on disk, e.g.  safe-analyze -decode web_payloads.zip -entry 1/uploads/shell.aspx | more")
		decodeEntry = flag.String("entry", "", "With -decode on a payload container, the entry (web_files.csv relative_path) to extract, e.g. 1/uploads/shell.aspx.")
		decodeOut   = flag.String("out", "", "With -decode, write the decoded content to this path instead of stdout. WARNING: writing a decoded malicious file to disk may trigger host AV/EDR to quarantine it.")
		rulesDirF   = flag.String("rules-dir", "", "Directory of external detection-rule files (*.yml/*.yaml) loaded on top of the built-in rules during --analyze. Defaults to a 'rules' folder next to the executable, or the SAFE_RULES_DIR environment variable.")
		versionFlag = flag.Bool("version", false, "Print the SAFE version and exit.")
		ftsFlag     = flag.Bool("fts", false, "For --serve: build and use a trigram full-text index for the report's free-text search (~10x faster keyword search that scales to large timelines). Trades disk — timeline.db grows several-fold and the first serve builds the index. Off by default (search uses a table scan). Also enabled by setting SAFE_FTS=1.")
	)

	flag.Parse()

	// Resolve --fts once: explicit flag, or SAFE_FTS truthy in the environment.
	enableFTS := *ftsFlag || isTruthyEnv(os.Getenv("SAFE_FTS"))

	if *versionFlag {
		fmt.Println("SAFE Analyzer v0.1.0")
		os.Exit(0)
	}

	// --decode: recover the original bytes of a quarantine-safe (.qtn) collected
	// file. Writes to stdout by default so a decoded web shell is not written back
	// to disk (where host AV would quarantine it) — pipe it to a pager/grep.
	if *decodeFile != "" {
		if err := runDecode(*decodeFile, *decodeEntry, *decodeOut); err != nil {
			fmt.Fprintf(os.Stderr, "Decode failed: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	// Reject ambiguous invocations early: at most one primary mode may be set,
	// and -tui only composes with -analyze (or runs standalone). Without this,
	// combining mode flags silently ran the first and dropped the rest.
	primaryModes := 0
	for _, set := range []bool{*verifyDir != "", *analyzeDir != "", *serveDir != "", *extractIocs != ""} {
		if set {
			primaryModes++
		}
	}
	if primaryModes > 1 {
		fmt.Fprintln(os.Stderr, "Error: choose one mode — -analyze, -serve, -verify, or -extract-iocs.")
		os.Exit(2)
	}
	if *tuiMode && (*verifyDir != "" || *serveDir != "" || *extractIocs != "") {
		fmt.Fprintln(os.Stderr, "Error: -tui can only accompany -analyze, or run alone to browse a report.")
		os.Exit(2)
	}

	// Smart auto-inference: no explicit mode selected. A bare case-folder argument
	// (optionally with modifier flags like -port/-fts) analyzes-then-serves, or
	// serves if already analyzed. This is now keyed off "no primary mode set"
	// rather than "no flags at all", so e.g. `safe-analyze -fts <case>` is handled
	// here instead of matching no branch and silently exiting. -tui alone is its
	// own mode, handled further down.
	noPrimaryMode := *verifyDir == "" && *analyzeDir == "" && *serveDir == "" && *extractIocs == "" && !*tuiMode
	if noPrimaryMode {
		caseDir := ""
		if flag.NArg() > 0 {
			caseDir = flag.Arg(0)
		} else {
			selected, err := tui_analyze.SelectCaseFolder()
			if err != nil || selected == "" {
				fmt.Println("No case folder selected. Exiting.")
				os.Exit(0)
			}
			caseDir = selected
		}

		// "Already analyzed" is decided by a real completion marker, not by the
		// mere existence of lab_report/ (which RunWithProgress creates before any
		// parser runs) — otherwise an analysis interrupted partway would be served
		// as if it were complete.
		if isAnalysisComplete(caseDir) {
			// Already analyzed, serve it
			fmt.Printf("Case %s is already analyzed. Starting report server...\n", caseDir)
			if err := html_report.StartServer(caseDir, *servePort, enableFTS); err != nil {
				fmt.Fprintf(os.Stderr, "HTML server error: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Not analyzed, analyze it first
			fmt.Printf("Case %s has not been analyzed. Starting analysis...\n", caseDir)
			fmt.Println("Initializing IOC intelligence packs...")
			indicators, err := ioc.LoadPacks("safe-iocs")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to load IOCs: %v\n", err)
			} else {
				fmt.Printf("Loaded %d active indicators from intelligence packs.\n\n", len(indicators))
			}

			runAnalyzer(caseDir, resolveRulesDir(*rulesDirF))
			
			// Auto-serve after analysis
			fmt.Println("\nAnalysis complete. Starting report server...")
			if err := html_report.StartServer(caseDir, *servePort, enableFTS); err != nil {
				fmt.Fprintf(os.Stderr, "HTML server error: %v\n", err)
				os.Exit(1)
			}
		}
		os.Exit(0)
	}

	// --- verify mode ---
	if *verifyDir != "" {
		fmt.Printf("Verifying: %s\n\n", *verifyDir)
		result, err := manifest.Verify(*verifyDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Files checked: %d\n", result.FilesChecked)
		if result.OK {
			fmt.Println("Status: OK — every file matches its recorded hash.")
			os.Exit(0)
		}
		fmt.Println("Status: FAILED")
		if len(result.Missing) > 0 {
			fmt.Println("\nMissing files (in manifest, not on disk):")
			for _, m := range result.Missing {
				fmt.Printf("  %s\n", m)
			}
		}
		if len(result.Mismatches) > 0 {
			fmt.Println("\nHash mismatches:")
			for _, m := range result.Mismatches {
				fmt.Printf("  %s\n", m)
			}
		}
		if len(result.Extra) > 0 {
			fmt.Println("\nExtra files (on disk, not in any manifest — possible tampering):")
			for _, e := range result.Extra {
				fmt.Printf("  %s\n", e)
			}
		}
		os.Exit(1)
	}

	// --extract-iocs: extract from PDF or Text file
	if *extractIocs != "" {
		fmt.Printf("Extracting IOCs from: %s\n\n", *extractIocs)
		result, err := ioc.ExtractFromFile(*extractIocs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Extraction failed: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Extracted %d IOC candidates.\n", len(result.IOCs))
		for _, c := range result.IOCs {
			fmt.Printf("  - [%s] %s (Confidence: %d)\n", c.Type, c.Value, c.Confidence)
		}

		// Resolve valid_from: use --report-date if provided, otherwise today.
		validFrom := time.Now().UTC()
		if *reportDate != "" {
			parsed, parseErr := time.Parse("2006-01-02", *reportDate)
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "Invalid --report-date %q: expected YYYY-MM-DD\n", *reportDate)
				os.Exit(2)
			}
			validFrom = parsed.UTC()
			fmt.Printf("Report date: %s (STIX valid_from)\n", validFrom.Format("2006-01-02"))
		} else {
			fmt.Printf("Report date: %s (today — use --report-date YYYY-MM-DD to set the publication date)\n",
				validFrom.Format("2006-01-02"))
		}

		// Convert to STIX 2.1
		bundle, err := result.ToSTIXBundle(validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "STIX Bundle creation failed: %v\n", err)
			os.Exit(3)
		}

		if err := os.MkdirAll("safe-iocs", 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create safe-iocs dir: %v\n", err)
			os.Exit(4)
		}

		// Save STIX JSON
		base := filepath.Base(*extractIocs)
		outName := strings.TrimSuffix(base, filepath.Ext(base)) + ".json"
		outPath := filepath.Join("safe-iocs", outName)

		bundleData, _ := json.MarshalIndent(bundle, "", "  ")
		if err := os.WriteFile(outPath, bundleData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write STIX file: %v\n", err)
			os.Exit(5)
		}

		fmt.Printf("\nSaved STIX 2.1 intelligence bundle to: %s\n", outPath)
		os.Exit(0)
	}

	// --analyze: run lab-side parsers against a collected case.
	if *analyzeDir != "" {
		fmt.Println("Initializing IOC intelligence packs...")
		indicators, err := ioc.LoadPacks("safe-iocs")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load IOCs: %v\n", err)
		} else {
			fmt.Printf("Loaded %d active indicators from intelligence packs.\n\n", len(indicators))
		}

		runAnalyzer(*analyzeDir, resolveRulesDir(*rulesDirF))
		if *tuiMode {
			if err := tui_analyze.RunWithViewer(*analyzeDir); err != nil {
				fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
				os.Exit(1)
			}
		}
		os.Exit(0)
	}

	// --serve: start local web server to view case report in browser
	if *serveDir != "" {
		if err := html_report.StartServer(*serveDir, *servePort, enableFTS); err != nil {
			fmt.Fprintf(os.Stderr, "HTML server error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// --tui (standalone mode): view case report in TUI, optionally specifying path as positional argument
	if *tuiMode {
		caseDir := ""
		if flag.NArg() > 0 {
			caseDir = flag.Arg(0)
		}
		if err := tui_analyze.RunWithViewer(caseDir); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

// resolveRulesDir picks the external detection-rules directory: the --rules-dir
// flag if set, else the SAFE_RULES_DIR environment variable, else a "rules"
// folder next to the executable. The directory need not exist — a missing one
// simply means only the built-in rules run.
// isTruthyEnv reports whether an environment-variable value should be read as
// "on" (for SAFE_FTS). Accepts 1/true/yes/on, case-insensitive; empty or
// anything else is off.
func isTruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// isAnalysisComplete reports whether a case folder has a finished analysis, used
// by the smart auto-inference path to decide serve-vs-reanalyze. It checks for
// output that only exists once analysis has actually run — analyzer_result.json
// and the lab-report manifest are both written after the parsers complete — so a
// run interrupted partway (which still leaves an empty/partial lab_report/ dir
// behind) is correctly treated as not analyzed and re-run rather than served as
// if complete.
func isAnalysisComplete(caseDir string) bool {
	labReportDir := filepath.Join(caseDir, "lab_report")
	for _, marker := range []string{"analyzer_result.json", "manifest.sha256"} {
		if info, err := os.Stat(filepath.Join(labReportDir, marker)); err == nil && info.Size() > 0 {
			return true
		}
	}
	return false
}

func resolveRulesDir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("SAFE_RULES_DIR"); env != "" {
		return env
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "rules")
	}
	return "rules"
}

func runAnalyzer(caseDir, rulesDir string) {
	fmt.Printf("SAFE Analyzer — parsing case folder\n")
	fmt.Printf("Case: %s\n\n", caseDir)

	registry := analyzer.NewRegistry()
	registry.Register(&analyzer.UserAssistParser{})
	registry.Register(&analyzer.PrefetchParser{})
	registry.Register(&analyzer.ProcessMemoryParser{})
	registry.Register(&analyzer.ComHijackParser{})
	registry.Register(&analyzer.WmiSubscriptionParser{})
	registry.Register(&analyzer.EvtxParser{})
	registry.Register(&analyzer.AmcacheParser{})
	registry.Register(&analyzer.ShellBagsParser{})
	registry.Register(&analyzer.ShimCacheParser{})
	registry.Register(&analyzer.SAMParser{})
	registry.Register(&analyzer.JumpListsParser{})
	registry.Register(&analyzer.BrowserHistoryParser{})
	registry.Register(&analyzer.BrowserCookiesParser{})
	registry.Register(&analyzer.BrowserDownloadsParser{})
	registry.Register(&analyzer.ScheduledTasksParser{})
	registry.Register(&analyzer.BamDamParser{})
	registry.Register(&analyzer.MFTParser{})
	registry.Register(&analyzer.USNParser{})
	registry.Register(&analyzer.IISLogParser{})

	lastLabel := ""
	onProgress := func(frac float64, label string) {
		// Print a bar line when the parser changes (append-only CLI; the
		// fraction streams finely but per-parser lines keep the output clean).
		if label != "" && label != lastLabel {
			lastLabel = label
			fmt.Printf("%s  %s\n", engine.ASCIIBar(int(frac*100), 100, 20), label)
		}
	}
	result, err := analyzer.RunWithProgress(caseDir, registry.All(), onProgress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Analyzer failed: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("Lab report: %s\n", result.LabReportDir)
	fmt.Printf("Duration:   %s\n\n", result.Duration)

	for _, p := range result.ParsersRun {
		fmt.Printf("[%s] %s (%s)\n",
			strings.ToUpper(p.Status), p.Name, p.Duration.Round(time.Millisecond))
		for _, out := range p.Outputs {
			fmt.Printf("  → %s\n", out)
		}
		if len(p.Stats) > 0 {
			// Sort keys for stable output.
			keys := make([]string, 0, len(p.Stats))
			for k := range p.Stats {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%d", k, p.Stats[k]))
			}
			fmt.Printf("  stats: %s\n", strings.Join(parts, ", "))
		}
		for _, e := range p.Errors {
			fmt.Printf("  [!] %s\n", e)
		}
	}

	// Run behavioral detection engine on the parsed lab report
	fmt.Println("\nRunning behavioral detection engine...")
	
	// Tier 2 Rules
	hitsT2, err := behavior.Run(result.LabReportDir, rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Behavior engine error (Tier 2): %v\n", err)
	}
	
	// Tier 3 Rules
	hitsT3, err := tier3.RunEngine(result.LabReportDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Behavior engine error (Tier 3): %v\n", err)
	}

	var allHits []behavior.Hit
	allHits = append(allHits, hitsT2...)
	allHits = append(allHits, hitsT3...)

	if len(allHits) > 0 {
		if err := behavior.WriteHits(result.LabReportDir, allHits); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write behavior hits: %v\n", err)
		} else {
			fmt.Printf("[BEHAVIOR] Found %d behavioral hits! See lab_report/behavior_hits.csv\n", len(allHits))
			// Inject the hits back into the timeline so they appear in EZ Timeline Explorer
			if err := timeline.AppendBehaviorToTimeline(result.LabReportDir); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to inject behavior hits into timeline: %v\n", err)
			} else {
				fmt.Println("[BEHAVIOR] Successfully injected hits into timeline.csv as ALERTS")
			}
		}
	} else {
		fmt.Printf("[BEHAVIOR] 0 hits found.\n")
	}

	// The behavioral engine above mutates lab_report/ (behavior_hits.csv,
	// timeline.csv alert injection) after analyzer.RunWithProgress already
	// wrote lab_report/manifest.sha256, so that manifest is stale the moment
	// hits exist. Regenerate it now that lab_report/ has reached its final
	// state, or --verify will report false tampering on every case with
	// behavioral hits.
	if err := analyzer.WriteLabReportManifest(result.LabReportDir); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to refresh lab_report manifest: %v\n", err)
	}
}
