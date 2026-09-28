package behavior

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Salahalza/SAFE/internal/csvutil"
)

// --- SAM-01: RogueLocalAccount ---
// Flags local accounts that look attacker-created, reading sam_users.csv from the
// SAM parser. Two signals: (1) a name that is a near-duplicate of another account
// — the classic blend-in an attacker uses to hide among real accounts, e.g.
// "support" alongside "supports"; and (2) a helpdesk/backdoor-style name. Built-in
// accounts (RID < 1000) are never flagged.
type RogueLocalAccount struct{}

func (r *RogueLocalAccount) ID() string       { return "SAM-01" }
func (r *RogueLocalAccount) Name() string     { return "Suspicious Local Account" }
func (r *RogueLocalAccount) MITRE() string    { return "T1136.001" }
func (r *RogueLocalAccount) Severity() string { return SeverityHigh }

var rogueAccountKeywords = []string{
	"support", "helpdesk", "backdoor", "hacker", "hacked", "malware",
}

type samAcct struct{ name, rid, class string }

func (r *RogueLocalAccount) Evaluate(dir string) []Hit {
	var accts []samAcct
	path := filepath.Join(dir, "sam_users.csv")
	_ = csvutil.ReadCSVHelper(path, func(header, row []string) error {
		u := csvutil.GetColIndex(header, "username")
		ri := csvutil.GetColIndex(header, "rid")
		cl := csvutil.GetColIndex(header, "account_class")
		if u == -1 || u >= len(row) {
			return nil
		}
		a := samAcct{name: row[u]}
		if ri != -1 && ri < len(row) {
			a.rid = row[ri]
		}
		if cl != -1 && cl < len(row) {
			a.class = row[cl]
		}
		accts = append(accts, a)
		return nil
	})
	if len(accts) == 0 {
		return nil
	}

	var hits []Hit
	seen := map[string]bool{}
	for _, a := range accts {
		if strings.Contains(strings.ToLower(a.class), "built-in") {
			continue // built-in accounts are not attacker-created
		}
		la := strings.ToLower(a.name)

		// Signal 1: look-alike of another account (strongest — a deliberate blend-in).
		twin := ""
		for _, b := range accts {
			if b.name != a.name && lookalikeName(la, strings.ToLower(b.name)) {
				twin = b.name
				break
			}
		}
		// Signal 2: helpdesk/backdoor-style keyword name.
		keyword := ""
		for _, k := range rogueAccountKeywords {
			if strings.Contains(la, k) {
				keyword = k
				break
			}
		}

		if twin == "" && keyword == "" || seen[la] {
			continue
		}
		seen[la] = true

		sev, reason := SeverityNotable, fmt.Sprintf("helpdesk/backdoor-style name (matched '%s')", keyword)
		if twin != "" {
			sev = SeverityHigh
			reason = fmt.Sprintf("name is a near-duplicate of existing account '%s' (blend-in)", twin)
		}
		hits = append(hits, Hit{
			RuleID:            r.ID(),
			Severity:          sev,
			MITRE:             r.MITRE(),
			Title:             r.Name(),
			EvidenceSource:    "sam_users.csv",
			EvidenceDetail:    fmt.Sprintf("Local account '%s' (RID %s) is suspicious: %s. Confirm whether an administrator created it.", a.name, a.rid, reason),
			TimelineSearchKey: a.name,
		})
	}
	return hits
}

// lookalikeName reports whether two lowercased account names are confusingly
// similar: one a short prefix-extension of the other (support/supports), or a
// single edit apart (admin/admln).
func lookalikeName(a, b string) bool {
	if a == b || a == "" || b == "" {
		return false
	}
	if strings.HasPrefix(a, b) || strings.HasPrefix(b, a) {
		d := len(a) - len(b)
		if d < 0 {
			d = -d
		}
		if d >= 1 && d <= 2 {
			return true
		}
	}
	return editDistance1(a, b)
}

// editDistance1 reports whether the Levenshtein distance between a and b is
// exactly 1 (one substitution, insertion, or deletion).
func editDistance1(a, b string) bool {
	la, lb := len(a), len(b)
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	if diff > 1 {
		return false
	}
	if la == lb {
		mismatches := 0
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				mismatches++
				if mismatches > 1 {
					return false
				}
			}
		}
		return mismatches == 1
	}
	// Insertion/deletion: walk both, allowing one skip in the longer string.
	if la < lb {
		a, b = b, a
		la, lb = lb, la
	}
	i, j, edits := 0, 0, 0
	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		edits++
		if edits > 1 {
			return false
		}
		i++ // skip one char in the longer string
	}
	return true
}
