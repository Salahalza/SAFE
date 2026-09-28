package analyzer

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"

	"www.velocidex.com/golang/regparser"
)

// SAMParser enumerates local user accounts from the SAM registry hive collected
// by registry_core (HKLM_SAM.hiv). Local-account enumeration is a core IR need —
// it is how attacker-created accounts (rogue "helpdesk"/service names, look-alike
// duplicates) are surfaced — and it was previously not automated at all.
//
// Account names live under SAM\Domains\Account\Users\Names as subkeys; the RID of
// each account is carried in the Type field of that subkey's default value (a
// SAM-specific encoding). The output feeds the SAM-01 rogue-account rule.
type SAMParser struct{}

func (p *SAMParser) Name() string { return "sam" }

func (p *SAMParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}

	samPath := firstGlob(caseDir, filepath.Join("modules", "*_registry_core", "HKLM_SAM.hiv"))
	if samPath == "" {
		return nil, stats, nil // SAM not collected in this profile
	}

	f, err := os.Open(samPath)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("open SAM hive: %w", err)}
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("parse SAM hive: %w", err)}
	}

	names := reg.OpenKey(`SAM\Domains\Account\Users\Names`)
	if names == nil {
		return nil, stats, []error{fmt.Errorf("SAM Names key not found in hive")}
	}

	if err := os.MkdirAll(labReportDir, 0o755); err != nil {
		return nil, stats, []error{err}
	}
	outPath := filepath.Join(labReportDir, "sam_users.csv")
	out, err := os.Create(outPath)
	if err != nil {
		return nil, stats, []error{err}
	}
	defer out.Close()

	w := csv.NewWriter(out)
	defer w.Flush()
	_ = w.Write([]string{"username", "rid", "account_class"})

	count := 0
	for _, sub := range names.Subkeys() {
		user := sub.Name()
		if user == "" {
			continue
		}
		// The RID is stored in the Type field of the subkey's default (unnamed)
		// value — a SAM-specific quirk, not a real registry value type.
		var rid uint32
		for _, v := range sub.Values() {
			if v.ValueName() == "" {
				rid = v.Type()
				break
			}
		}
		// RIDs below 1000 are the built-in accounts (Administrator 500, Guest 501,
		// DefaultAccount, etc.); >= 1000 are accounts created on this machine.
		class := "built-in"
		if rid >= 1000 {
			class = "local (created on host)"
		}
		_ = w.Write([]string{user, fmt.Sprintf("%d", rid), class})
		count++
	}
	stats["accounts"] = count

	return []string{outPath}, stats, nil
}
