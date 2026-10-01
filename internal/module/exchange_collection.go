package module

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/roles"
)

// ExchangeCollection collects Microsoft Exchange server logs — transport
// (message tracking, protocol, connectivity) and the general Logging tree — for
// lab-side analysis of mail-flow and management activity during an incident.
//
// Like the IIS collector it is discovery-first: the install root is read from
// the Exchange Setup registry key (MsiInstallPath) rather than assumed, so a
// relocated install is still collected. It copies raw log bytes only; any
// interpretation happens in the lab (architecture principle #1).
//
// Note this collects the transport/logging artifacts specifically. Exchange's
// OWA/ECP web surface is IIS-hosted and is covered by iis_collection, which runs
// in the same server profile.
type ExchangeCollection struct{}

func (m *ExchangeCollection) Name() string              { return "exchange_collection" }
func (m *ExchangeCollection) Priority() Priority        { return PriorityHigh }
func (m *ExchangeCollection) TimeBudget() time.Duration { return 20 * time.Minute }
func (m *ExchangeCollection) RequiresVSS() bool         { return true }

// Applies reports whether Exchange is installed. On any other host the module
// cleanly no-ops. Detection is registry-based live host state, valid during
// planning before a shadow exists.
func (m *ExchangeCollection) Applies(ctx *Context) (bool, string) {
	if !ctx.Live {
		if roles.IsExchangeServerImage(ctx.Root) {
			return true, ""
		}
		return false, "image is not an Exchange server (ExchangeServer\\v15 absent in SOFTWARE hive)"
	}
	if roles.IsExchangeServer() {
		return true, ""
	}
	return false, "target is not an Exchange server (ExchangeServer\\v15 registry key absent)"
}

// exchangeLogSubdirs are the install-relative log trees collected, most
// incident-relevant first. TransportRoles/Logs holds message tracking and the
// SMTP/POP/IMAP protocol logs; Logging is the broad management/health tree.
var exchangeLogSubdirs = []string{
	`TransportRoles\Logs`,
	`Logging`,
}

const (
	// maxExchangeFileBytes caps a single log file copy; an Exchange log file
	// rarely exceeds this and a runaway one should not be pulled whole.
	maxExchangeFileBytes = 200 * 1024 * 1024
	// maxExchangeTotalBytes bounds the whole module so an active server with
	// months of retained logs cannot balloon the case. When hit, collection
	// stops and a warning records how many files were skipped.
	maxExchangeTotalBytes = 4 * 1024 * 1024 * 1024
)

type exchangeInfo struct {
	InstallPath  string `json:"install_path"`
	FilesCopied  int    `json:"files_copied"`
	FilesSkipped int    `json:"files_skipped"`
	BytesCopied  int64  `json:"bytes_copied"`
	BudgetHit    bool   `json:"budget_hit"`
}

func (m *ExchangeCollection) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Findings:   []Finding{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}
	if ctx.Root == "" {
		result.AddWarning("root", "no evidence root available; module requires an evidence root")
		result.Errors = append(result.Errors, "no evidence root available")
		finalize(&result, started, ctx.Ctx)
		return result
	}

	install := ""
	if ctx.Live {
		install = roles.ExchangeInstallPath()
	} else {
		install = roles.ExchangeInstallPathImage(ctx.Root)
	}
	if install == "" {
		install = `C:\Program Files\Microsoft\Exchange Server\V15`
		result.AddWarning("discovery", "Exchange install path not found; using default install root")
	}

	info := exchangeInfo{InstallPath: install}
	root := ctx.Root

	// used tracks accepted bytes live across every subtree so the total-size
	// budget takes effect within a single walk, not only between subtrees. keep
	// runs before each copy, so incrementing it here mirrors what will be copied.
	var used int64
	keep := func(name string, size int64) bool {
		if info.BudgetHit {
			info.FilesSkipped++
			return false
		}
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".log") && !strings.HasSuffix(lower, ".csv") {
			return false
		}
		if size > maxExchangeFileBytes {
			info.FilesSkipped++
			return false
		}
		if used+size > maxExchangeTotalBytes {
			info.BudgetHit = true
			info.FilesSkipped++
			return false
		}
		used += size
		return true
	}

	for i, sub := range exchangeLogSubdirs {
		live := filepath.Join(install, sub)
		rootSrc, err := mapToRoot(live, root)
		if err != nil {
			result.AddWarning(sub, fmt.Sprintf("path map failed: %v", err))
			continue
		}
		if fi, statErr := os.Stat(rootSrc); statErr != nil || !fi.IsDir() {
			result.AddInfo(sub, "log subtree not present")
			continue
		}
		dst := filepath.Join(ctx.OutputDir, "logs", strings.ReplaceAll(sub, `\`, "_"))
		n, b, errs := collectFilteredTree(ctx, rootSrc, dst, keep)
		info.FilesCopied += n
		info.BytesCopied += b
		for _, e := range errs {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sub, e))
		}
		ctx.ReportProgress(i+1, len(exchangeLogSubdirs), used)
	}

	result.BulkFiles += info.FilesCopied
	if info.BudgetHit {
		result.AddWarning(m.Name(), fmt.Sprintf("collection size budget (%d bytes) reached; %d file(s) skipped", maxExchangeTotalBytes, info.FilesSkipped))
	}

	// Discovery/audit record.
	if data, err := json.MarshalIndent(info, "", "  "); err == nil {
		recPath := filepath.Join(ctx.OutputDir, "exchange_info.json")
		if err := os.WriteFile(recPath, data, 0o644); err == nil {
			if art, err := describeArtifact(recPath); err == nil {
				result.Artifacts = append(result.Artifacts, art)
			}
		}
	}

	result.AddInfo(m.Name(), fmt.Sprintf("collected %d Exchange log file(s) (%d bytes) from %s", info.FilesCopied, info.BytesCopied, install))
	if info.FilesCopied == 0 {
		result.AddWarning(m.Name(), "no Exchange log files collected — verify the install path and log retention")
	}

	finalize(&result, started, ctx.Ctx)
	return result
}
