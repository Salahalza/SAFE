package behavior

// Rule loading: embedded defaults overlaid by external rule files.
//
// The 13 row-wise detections that used to be hardcoded Go structs now ship as
// YAML under defaults/, embedded into the binary so a bare safe-analyze.exe
// still detects everything with no external files present. An analyst can then
// drop *.yml / *.yaml files into the rules directory to add new rules or, by
// reusing a built-in's id, override or (with enabled:false) disable one — all
// without recompiling.

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed defaults/*.yml
var defaultRuleFS embed.FS

// ruleFileDoc is a rule file's top-level shape. A file is either a single rule
// (its fields inline) or a `rules:` list of them.
type ruleFileDoc struct {
	ruleSpec `yaml:",inline"`
	Rules    []ruleSpec `yaml:"rules"`
}

// specsFromDoc returns the rules a decoded file contributes: the `rules:` list
// if present, otherwise the single inline rule (when it has an id).
func specsFromDoc(doc ruleFileDoc) []ruleSpec {
	if len(doc.Rules) > 0 {
		return doc.Rules
	}
	if doc.ID != "" {
		return []ruleSpec{doc.ruleSpec}
	}
	return nil
}

// parseRuleBytes decodes and validates every rule in one file's bytes.
func parseRuleBytes(data []byte) ([]ruleSpec, error) {
	var doc ruleFileDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	specs := specsFromDoc(doc)
	if len(specs) == 0 {
		return nil, fmt.Errorf("no rules found (missing 'id' or 'rules:')")
	}
	for i := range specs {
		if err := validateSpec(&specs[i]); err != nil {
			return nil, err
		}
	}
	return specs, nil
}

// validateSpec checks required fields, normalizes severity, and validates the
// condition tree (compiling any regex).
func validateSpec(s *ruleSpec) error {
	if s.ID == "" {
		return fmt.Errorf("rule missing 'id'")
	}
	if s.Title == "" {
		return fmt.Errorf("rule %s missing 'title'", s.ID)
	}
	if s.Source == "" && len(s.Sources) == 0 {
		return fmt.Errorf("rule %s missing 'source' or 'sources'", s.ID)
	}
	if s.SeverityFrom == "" {
		s.Severity = strings.ToUpper(strings.TrimSpace(s.Severity))
		switch s.Severity {
		case SeverityHigh, SeverityNotable, SeverityInfo:
		default:
			return fmt.Errorf("rule %s has invalid severity %q (want HIGH/NOTABLE/INFO or severity_from)", s.ID, s.Severity)
		}
	}
	if s.Match != nil {
		if err := s.Match.validate(); err != nil {
			return fmt.Errorf("rule %s: %w", s.ID, err)
		}
	}
	return nil
}

// loadDeclRules builds the declarative rule set: embedded defaults first, then
// external files from rulesDir overlaid on top. Any file that fails to parse is
// skipped and reported in warnings rather than aborting detection. Rules are
// returned in a stable order (defaults in filename order, then externally-added
// rules in load order). warnings is human-readable, for the caller to surface.
func loadDeclRules(rulesDir string) (rules []Rule, warnings []string) {
	// Ordered map: keep insertion order but allow override-by-id.
	order := []string{}
	byID := map[string]*declRule{}
	// seen tracks every id ever added to `order`, independent of byID. A disabled
	// rule is deleted from byID but its id must stay recorded here, otherwise a
	// later re-registration of the same id (disable-then-re-enable, across files
	// or within one rules list) would find it "absent from byID" and append it to
	// `order` a second time — emitting the rule twice in the final set, doubling
	// every hit it produces.
	seen := map[string]bool{}
	upsert := func(spec ruleSpec, origin string) {
		if !seen[spec.ID] {
			seen[spec.ID] = true
			order = append(order, spec.ID)
		}
		if !spec.enabledOrDefault() {
			delete(byID, spec.ID) // enabled:false removes a rule (e.g. disable a built-in)
			return
		}
		byID[spec.ID] = &declRule{spec: spec, origin: origin}
	}

	// 1. Embedded defaults.
	defFiles, _ := defaultRuleFS.ReadDir("defaults")
	names := make([]string, 0, len(defFiles))
	for _, f := range defFiles {
		names = append(names, f.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := defaultRuleFS.ReadFile("defaults/" + name)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("built-in rule %s unreadable: %v", name, err))
			continue
		}
		specs, err := parseRuleBytes(data)
		if err != nil {
			// A broken embedded default is a build-time bug, not a field
			// condition — surface it loudly but keep going.
			warnings = append(warnings, fmt.Sprintf("built-in rule %s invalid: %v", name, err))
			continue
		}
		for _, s := range specs {
			upsert(s, "built-in")
		}
	}

	// 2. External overlay.
	warnings = append(warnings, loadExternalDir(rulesDir, byID, &order, upsert)...)

	out := make([]Rule, 0, len(order))
	for _, id := range order {
		if r, ok := byID[id]; ok {
			out = append(out, r)
		}
	}
	return out, warnings
}

// loadExternalDir reads every *.yml/*.yaml in rulesDir (sorted) and upserts the
// rules it finds. A missing directory is not an error (the common field case).
func loadExternalDir(rulesDir string, byID map[string]*declRule, order *[]string, upsert func(ruleSpec, string)) []string {
	var warnings []string
	if rulesDir == "" {
		return nil
	}
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(rulesDir, pat))
		files = append(files, m...)
	}
	if len(files) == 0 {
		return nil
	}
	sort.Strings(files)
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipped rule file %s: %v", filepath.Base(path), err))
			continue
		}
		specs, err := parseRuleBytes(data)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipped rule file %s: %v", filepath.Base(path), err))
			continue
		}
		for _, s := range specs {
			if _, existed := byID[s.ID]; existed {
				warnings = append(warnings, fmt.Sprintf("rule %s from %s overrides an earlier rule of the same id", s.ID, filepath.Base(path)))
			}
			upsert(s, filepath.Base(path))
		}
	}
	return warnings
}
