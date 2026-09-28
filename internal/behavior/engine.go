package behavior

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Salahalza/SAFE/internal/csvutil"
)

// Run executes all behavioral rules against the parsed lab report directory and
// returns the hits found. Rules come from two places: native Go rules for the
// stateful/correlation detections that cannot be expressed declaratively, and
// declarative YAML rules — the embedded defaults plus any external files found
// in rulesDir (pass "" to use only the embedded defaults). Non-fatal rule-load
// warnings (a malformed external file, an id override) are printed to stderr so
// a bad rule file degrades gracefully instead of aborting detection.
func Run(labReportDir, rulesDir string) ([]Hit, error) {
	// Native Go rules: brute-force counting, external-IP math, and cross-CSV
	// correlation — logic that is not a per-row column predicate and so stays
	// in code rather than moving to the YAML rule format.
	rules := []Rule{
		&RogueLocalAccount{},
		&AuthBruteForce{},
		&ExternalSuccessLogon{},
		&IISWebShellFile{},
		&IISUploadDirScript{},
		&IISWebShellAccess{},
		&IISLolBinRequest{},
		&IISProxyShellSSRF{},
		&IISAnonPowerShell{},
		&IISAnonECP{},
	}

	// Declarative rules: embedded defaults overlaid by external files.
	declRules, warnings := loadDeclRules(rulesDir)
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "[rules] %s\n", w)
	}
	rules = append(rules, declRules...)

	var allHits []Hit

	for _, rule := range rules {
		hits := rule.Evaluate(labReportDir)
		allHits = append(allHits, hits...)
	}

	if len(allHits) == 0 {
		return nil, nil
	}

	return allHits, nil
}

// severityOrder ranks severities for output sorting; unknown severities sort
// last so a malformed hit never floats above a real HIGH.
var severityOrder = map[string]int{"HIGH": 0, "NOTABLE": 1, "INFO": 2}

// lessHit is a total ordering over hits. Sorting on (severity, RuleID) alone
// left same-rule hits in whatever order the rules produced them — and because
// several rules iterate maps, that order is not stable between analyze runs,
// so re-analyzing a case reshuffled rows within a (severity, RuleID) group.
// Extending the tiebreaker across the remaining fields makes the order a pure
// function of the hit set, so behavior_hits.csv is byte-for-byte reproducible.
func lessHit(a, b Hit) bool {
	sa, oka := severityOrder[a.Severity]
	sb, okb := severityOrder[b.Severity]
	if !oka {
		sa = len(severityOrder)
	}
	if !okb {
		sb = len(severityOrder)
	}
	if sa != sb {
		return sa < sb
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.EvidenceSource != b.EvidenceSource {
		return a.EvidenceSource < b.EvidenceSource
	}
	if a.TimelineSearchKey != b.TimelineSearchKey {
		return a.TimelineSearchKey < b.TimelineSearchKey
	}
	if a.EvidenceDetail != b.EvidenceDetail {
		return a.EvidenceDetail < b.EvidenceDetail
	}
	if a.Title != b.Title {
		return a.Title < b.Title
	}
	return a.MITRE < b.MITRE
}

// SortHits orders hits into the canonical, deterministic output order used for
// behavior_hits.csv (HIGH > NOTABLE > INFO, then a full-field tiebreaker).
func SortHits(hits []Hit) {
	sort.Slice(hits, func(i, j int) bool { return lessHit(hits[i], hits[j]) })
}

// WriteHits writes the list of behavioral hits to behavior_hits.csv.
func WriteHits(labReportDir string, allHits []Hit) error {
	SortHits(allHits)

	outPath := filepath.Join(labReportDir, "behavior_hits.csv")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create behavior_hits.csv: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	// Write header
	_ = w.Write([]string{"rule_id", "severity", "mitre_technique", "title", "evidence_source", "evidence_detail", "timeline_search_key"})

	for _, h := range allHits {
		// Title/EvidenceSource/EvidenceDetail/TimelineSearchKey echo attacker-
		// controlled evidence text (task names, command lines, file paths from
		// the compromised host), so quote them against CSV formula injection when
		// the analyst opens behavior_hits.csv in a spreadsheet.
		_ = w.Write([]string{
			h.RuleID,
			h.Severity,
			h.MITRE,
			csvutil.CsvSafe(h.Title),
			csvutil.CsvSafe(h.EvidenceSource),
			csvutil.CsvSafe(h.EvidenceDetail),
			csvutil.CsvSafe(h.TimelineSearchKey),
		})
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush behavior_hits.csv: %w", err)
	}

	return nil
}
