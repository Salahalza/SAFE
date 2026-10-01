package html_report

import (
	"encoding/csv"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// artifactFile is one artifact CSV as presented in the Explorer sidebar: its
// lab_report-relative path plus a data-row count that lets the analyst see, at a
// glance, which artifacts actually hold evidence. On a real case the EVTX group
// alone is ~116 channels, almost all empty; the count is the signal that tells
// Security (200k rows) apart from a channel that never logged an event.
type artifactFile struct {
	Path string `json:"path"`
	Rows int    `json:"rows"`
}

// rowCountCache memoizes the data-row count (records minus the header) of an
// artifact CSV, keyed by absolute path and validated against the file's mtime.
// Counting a multi-hundred-MB CSV means tokenizing it once; the cache makes the
// Artifact Explorer sidebar pay that cost only on the first open (and again only
// if a re-analyze rewrites the file, which changes its mtime).
type rowCountCache struct {
	mu    sync.Mutex
	items map[string]rowCountEntry
}

type rowCountEntry struct {
	count int
	mtime time.Time
}

func newRowCountCache() *rowCountCache {
	return &rowCountCache{items: make(map[string]rowCountEntry)}
}

// count returns the number of data rows in the CSV at absPath, from cache when
// the file is unchanged since it was counted, otherwise by streaming it once.
func (c *rowCountCache) count(absPath string, mtime time.Time) int {
	c.mu.Lock()
	if e, ok := c.items[absPath]; ok && e.mtime.Equal(mtime) {
		c.mu.Unlock()
		return e.count
	}
	c.mu.Unlock()

	n := countCSVRows(absPath)

	c.mu.Lock()
	c.items[absPath] = rowCountEntry{count: n, mtime: mtime}
	c.mu.Unlock()
	return n
}

// countCSVRows streams a CSV and returns its data-row count (total records less
// the header row). It reuses one record buffer and tolerates ragged rows so a
// giant file is tokenized without per-row allocation and a malformed file yields
// the best-effort count reached so far rather than aborting the sidebar. Using a
// real CSV reader (not a raw newline count) keeps the tally correct even when a
// field contains an embedded newline.
func countCSVRows(absPath string) int {
	f, err := os.Open(absPath)
	if err != nil {
		return 0
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true

	n := 0
	for {
		_, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		n++
	}
	if n > 0 {
		n-- // exclude the header row
	}
	return n
}

// evtxPriorityChannels lists the Windows event-log channels that matter most in
// an intrusion investigation, in the order an analyst usually reaches for them.
// A channel not in this list sorts after all of these. Matching is on the CSV
// base name (no extension), case-insensitively, against the real channel-derived
// file names SAFE's EVTX parser writes.
var evtxPriorityChannels = []string{
	"Security",
	"Microsoft-Windows-PowerShell_Operational",
	"Windows PowerShell",
	"Microsoft-Windows-Sysmon_Operational",
	"System",
	"Microsoft-Windows-TaskScheduler_Operational",
	"Microsoft-Windows-TaskScheduler_Maintenance",
	"Microsoft-Windows-WinRM_Operational",
	"Microsoft-Windows-WMI-Activity_Operational",
	"Microsoft-Windows-TerminalServices-LocalSessionManager_Operational",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager_Operational",
	"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS_Operational",
	"Microsoft-Windows-SMBServer_Security",
	"Microsoft-Windows-SmbClient_Security",
	"Microsoft-Windows-Bits-Client_Operational",
	"Microsoft-Windows-Windows Defender_Operational",
	"Application",
}

const evtxNotPriority = 1 << 30

// evtxPriority returns the curated rank of a channel CSV (lower = higher value),
// or evtxNotPriority when the channel isn't on the curated list.
func evtxPriority(relPath string) int {
	base := relPath[strings.LastIndex(relPath, "/")+1:]
	base = strings.TrimSuffix(base, ".csv")
	for i, name := range evtxPriorityChannels {
		if strings.EqualFold(base, name) {
			return i
		}
	}
	return evtxNotPriority
}

// orderArtifactFiles sorts one folder's files in place. The EVTX group — the
// only group large enough to bury signal — floats its curated high-value
// channels to the top (in curated order), then orders the remaining channels by
// row count, so a busy but un-curated channel still rises above the empty ones.
// Every other group keeps a stable alphabetical order.
func orderArtifactFiles(folder string, files []artifactFile) {
	if strings.EqualFold(folder, "Evtx") {
		sort.SliceStable(files, func(a, b int) bool {
			ra, rb := evtxPriority(files[a].Path), evtxPriority(files[b].Path)
			if ra != rb {
				return ra < rb
			}
			if ra == evtxNotPriority && files[a].Rows != files[b].Rows {
				return files[a].Rows > files[b].Rows
			}
			return strings.ToLower(files[a].Path) < strings.ToLower(files[b].Path)
		})
		return
	}
	sort.SliceStable(files, func(a, b int) bool {
		return strings.ToLower(files[a].Path) < strings.ToLower(files[b].Path)
	})
}
