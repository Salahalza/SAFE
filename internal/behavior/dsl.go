package behavior

// Declarative detection rules.
//
// SAFE's behavioral engine loads detection rules from external YAML files at
// analyze time (see dsl_load.go), so an analyst can add or tune rules by
// dropping a file in the rules directory — no recompile. This file defines the
// on-disk rule schema, the per-row condition-tree matcher, and the adapter that
// makes a loaded rule satisfy the same Rule interface the native Go rules use.
//
// Rules are pure DATA, not code: a rule can only read a CSV column and compare
// it to strings the author wrote. There is no scripting surface, so loading a
// rule file from another analyst cannot execute anything. Regular expressions
// run on Go's RE2 engine (linear time), so a hostile pattern cannot cause
// catastrophic backtracking. This is deliberate — it keeps the "signature
// folder" model safe to share, consistent with the defensive charter.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Salahalza/SAFE/internal/csvutil"
)

// ruleSpec is the on-disk YAML shape of one detection rule.
//
// A rule targets one or more CSVs under lab_report/ (source / sources, each a
// literal path or a glob), evaluates match against every row, and emits a Hit
// for each matching row. severity is used unless severity_from names a column
// whose value (HIGH/NOTABLE/INFO) supplies the severity per row.
type ruleSpec struct {
	ID           string    `yaml:"id"`
	Title        string    `yaml:"title"`
	MITRE        string    `yaml:"mitre"`
	Severity     string    `yaml:"severity"`
	SeverityFrom string    `yaml:"severity_from"`
	Source       string    `yaml:"source"`
	Sources      []string  `yaml:"sources"`
	Match        *condNode `yaml:"match"`
	Evidence     string    `yaml:"evidence"`
	EvidenceSrc  string    `yaml:"evidence_source"`
	TimelineKey  string    `yaml:"timeline_key"`
	Enabled      *bool     `yaml:"enabled"`
}

// enabledOrDefault reports whether the rule is active (default true).
func (s ruleSpec) enabledOrDefault() bool { return s.Enabled == nil || *s.Enabled }

// condNode is one node of a rule's condition tree. A node is exactly one of:
// an "all" (AND) block, an "any" (OR) block, a "not" negation, or a leaf that
// tests one CSV column with one operator. validate() enforces that shape.
type condNode struct {
	All []condNode `yaml:"all"`
	Any []condNode `yaml:"any"`
	Not *condNode  `yaml:"not"`

	// Leaf: which column, and one comparison operator.
	Field          string   `yaml:"field"`
	Equals         *string  `yaml:"equals"`
	NotEquals      *string  `yaml:"not_equals"`
	In             []string `yaml:"in"`
	NotIn          []string `yaml:"not_in"`
	Contains       *string  `yaml:"contains"`
	NotContains    *string  `yaml:"not_contains"`
	ContainsAny    []string `yaml:"contains_any"`
	NotContainsAny []string `yaml:"not_contains_any"`
	StartsWith     *string  `yaml:"starts_with"`
	Regex          *string  `yaml:"regex"`
	Exists         *bool    `yaml:"exists"`

	re *regexp.Regexp // compiled form of Regex, filled by validate()
}

// isCombinator reports whether this node is an all/any/not block rather than a leaf.
func (n *condNode) isCombinator() bool {
	return len(n.All) > 0 || len(n.Any) > 0 || n.Not != nil
}

// validate checks the node's shape and pre-compiles any regex. String matching
// is case-insensitive throughout (matching the native Go rules, which lowercase
// both sides), so a regex is compiled with the (?i) flag.
func (n *condNode) validate() error {
	if n.isCombinator() {
		// A combinator must not also carry leaf fields — that is almost always
		// an authoring mistake (indentation) and would silently ignore the leaf.
		if n.hasLeafOp() || n.Field != "" {
			return fmt.Errorf("node mixes a combinator (all/any/not) with leaf fields")
		}
		forms := 0
		if len(n.All) > 0 {
			forms++
		}
		if len(n.Any) > 0 {
			forms++
		}
		if n.Not != nil {
			forms++
		}
		if forms > 1 {
			return fmt.Errorf("node has more than one of all/any/not")
		}
		for i := range n.All {
			if err := n.All[i].validate(); err != nil {
				return err
			}
		}
		for i := range n.Any {
			if err := n.Any[i].validate(); err != nil {
				return err
			}
		}
		if n.Not != nil {
			return n.Not.validate()
		}
		return nil
	}
	// Leaf.
	if n.Field == "" {
		return fmt.Errorf("leaf condition missing 'field'")
	}
	if !n.hasLeafOp() {
		return fmt.Errorf("leaf condition on field %q has no operator", n.Field)
	}
	if n.Regex != nil {
		re, err := regexp.Compile("(?i)" + *n.Regex)
		if err != nil {
			return fmt.Errorf("invalid regex %q: %w", *n.Regex, err)
		}
		n.re = re
	}
	return nil
}

// hasLeafOp reports whether any leaf operator is set on this node.
func (n *condNode) hasLeafOp() bool {
	return n.Equals != nil || n.NotEquals != nil || n.In != nil || n.NotIn != nil ||
		n.Contains != nil || n.NotContains != nil || n.ContainsAny != nil ||
		n.NotContainsAny != nil || n.StartsWith != nil || n.Regex != nil || n.Exists != nil
}

// fieldLookup returns a column's value for the current row and whether the
// column exists in this CSV.
type fieldLookup func(field string) (value string, present bool)

// eval evaluates the node against one row.
func (n *condNode) eval(get fieldLookup) bool {
	if len(n.All) > 0 {
		for i := range n.All {
			if !n.All[i].eval(get) {
				return false
			}
		}
		return true
	}
	if len(n.Any) > 0 {
		for i := range n.Any {
			if n.Any[i].eval(get) {
				return true
			}
		}
		return false
	}
	if n.Not != nil {
		return !n.Not.eval(get)
	}
	return n.evalLeaf(get)
}

// evalLeaf applies this leaf's single operator. All string comparisons are
// case-insensitive.
func (n *condNode) evalLeaf(get fieldLookup) bool {
	raw, present := get(n.Field)
	if n.Exists != nil {
		return present == *n.Exists
	}
	v := strings.ToLower(raw)
	switch {
	case n.Equals != nil:
		return v == strings.ToLower(*n.Equals)
	case n.NotEquals != nil:
		return v != strings.ToLower(*n.NotEquals)
	case n.In != nil:
		return containsFold(n.In, raw)
	case n.NotIn != nil:
		return !containsFold(n.NotIn, raw)
	case n.Contains != nil:
		return strings.Contains(v, strings.ToLower(*n.Contains))
	case n.NotContains != nil:
		return !strings.Contains(v, strings.ToLower(*n.NotContains))
	case n.ContainsAny != nil:
		return containsAnyFold(v, n.ContainsAny)
	case n.NotContainsAny != nil:
		return !containsAnyFold(v, n.NotContainsAny)
	case n.StartsWith != nil:
		return strings.HasPrefix(v, strings.ToLower(*n.StartsWith))
	case n.re != nil:
		return n.re.MatchString(raw)
	}
	return false
}

func containsFold(set []string, v string) bool {
	for _, s := range set {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether lowered haystack contains any of needles
// (each lowered).
func containsAnyFold(loweredHaystack string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(loweredHaystack, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

// declRule adapts a validated ruleSpec to the Rule interface.
type declRule struct {
	spec   ruleSpec
	origin string // file the rule came from ("built-in" for embedded defaults)
}

func (r *declRule) ID() string       { return r.spec.ID }
func (r *declRule) Name() string     { return r.spec.Title }
func (r *declRule) MITRE() string    { return r.spec.MITRE }
func (r *declRule) Severity() string { return r.spec.Severity }

// Evaluate runs the rule over every row of its source CSV(s) and returns a Hit
// for each match. Missing source files yield no hits (the same silent skip the
// native Go rules use when an artifact was not collected).
func (r *declRule) Evaluate(dir string) []Hit {
	var hits []Hit
	for _, path := range r.resolveSources(dir) {
		_ = csvutil.ReadCSVHelper(path, func(header, row []string) error {
			get := func(field string) (string, bool) {
				idx := csvutil.GetColIndex(header, field)
				if idx == -1 || idx >= len(row) {
					return "", false
				}
				return row[idx], true
			}
			if r.spec.Match != nil && !r.spec.Match.eval(get) {
				return nil
			}
			sev, ok := r.severityFor(get)
			if !ok {
				return nil
			}
			hits = append(hits, Hit{
				RuleID:            r.spec.ID,
				Severity:          sev,
				MITRE:             r.spec.MITRE,
				Title:             r.spec.Title,
				EvidenceSource:    r.evidenceSource(path, dir, header, row),
				EvidenceDetail:    renderTemplate(r.spec.Evidence, header, row, path, dir),
				TimelineSearchKey: renderTemplate(r.spec.TimelineKey, header, row, path, dir),
			})
			return nil
		})
	}
	return hits
}

// severityFor resolves a row's severity. With severity_from set, the named
// column supplies it and a row whose value is not HIGH/NOTABLE/INFO is skipped
// (ok=false), mirroring the tier-driven native rules. Otherwise the rule's
// fixed severity is used.
func (r *declRule) severityFor(get fieldLookup) (string, bool) {
	if r.spec.SeverityFrom == "" {
		return r.spec.Severity, true
	}
	raw, _ := get(r.spec.SeverityFrom)
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case SeverityHigh:
		return SeverityHigh, true
	case SeverityNotable:
		return SeverityNotable, true
	case SeverityInfo:
		return SeverityInfo, true
	}
	return "", false
}

// resolveSources expands source / sources (literal paths or globs, relative to
// lab_report/) to the set of existing CSV files, de-duplicated and ordered.
func (r *declRule) resolveSources(dir string) []string {
	patterns := r.spec.Sources
	if r.spec.Source != "" {
		patterns = append([]string{r.spec.Source}, patterns...)
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range patterns {
		matches, _ := filepath.Glob(filepath.Join(dir, filepath.FromSlash(p)))
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// evidenceSource produces the Hit.EvidenceSource string. An explicit
// evidence_source template wins; otherwise a single literal source reports that
// path verbatim and a glob/multi-source reports the matched file's base name.
func (r *declRule) evidenceSource(path, dir string, header, row []string) string {
	if r.spec.EvidenceSrc != "" {
		return renderTemplate(r.spec.EvidenceSrc, header, row, path, dir)
	}
	if r.spec.Source != "" && len(r.spec.Sources) == 0 && !strings.ContainsAny(r.spec.Source, "*?[") {
		return r.spec.Source
	}
	return filepath.Base(path)
}

// renderTemplate substitutes {column} tokens with the row's value for that
// column (case-insensitive). {source_file} and {source_path} expand to the
// matched CSV's base name and its path relative to lab_report/. Unknown tokens
// render empty.
func renderTemplate(tmpl string, header, row []string, path, baseDir string) string {
	if tmpl == "" || !strings.Contains(tmpl, "{") {
		return tmpl
	}
	var b strings.Builder
	for i := 0; i < len(tmpl); {
		if tmpl[i] == '{' {
			if j := strings.IndexByte(tmpl[i:], '}'); j > 1 {
				b.WriteString(resolveToken(tmpl[i+1:i+j], header, row, path, baseDir))
				i += j + 1
				continue
			}
		}
		b.WriteByte(tmpl[i])
		i++
	}
	return b.String()
}

func resolveToken(name string, header, row []string, path, baseDir string) string {
	switch name {
	case "source_file":
		return filepath.Base(path)
	case "source_path":
		if rel, err := filepath.Rel(baseDir, path); err == nil {
			return filepath.ToSlash(rel)
		}
		return filepath.Base(path)
	}
	return csvutil.SafeIndex(row, csvutil.GetColIndex(header, name))
}
