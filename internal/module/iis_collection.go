package module

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/evidence"
	"github.com/Salahalza/SAFE/internal/roles"
)

// IISCollection collects IIS web-server evidence: the server configuration
// (applicationHost.config and its siblings), the W3C request logs, and the
// server-executable script files sitting in each site's web root. Together these
// let the lab-side IIS parser and behavioral rules hunt web shells and reconstruct
// what was requested — without doing any interpretation on the target itself
// (architecture principle #1).
//
// The module is discovery-first: it reads the *configured* log directories and
// site physical paths out of applicationHost.config rather than assuming the
// defaults, because a relocated install (custom log path, non-default web root)
// is exactly the case that matters in a real intrusion and the one where a
// hardcoded default silently collects nothing. Default locations are still tried
// as a fallback so a parse miss never yields an empty collection.
type IISCollection struct{}

func (m *IISCollection) Name() string              { return "iis_collection" }
func (m *IISCollection) Priority() Priority        { return PriorityHigh }
func (m *IISCollection) TimeBudget() time.Duration { return 20 * time.Minute }
func (m *IISCollection) RequiresVSS() bool         { return true }

// Applies reports whether IIS is installed on this target. On a host without the
// IIS role the module cleanly no-ops instead of copying nothing and emitting
// criticals, so a single server profile runs safely against any server. Detection
// is registry-based (live host state), which is valid here because the engine
// evaluates Applies during planning before any shadow exists.
func (m *IISCollection) Applies(ctx *Context) (bool, string) {
	if !ctx.Live {
		if roles.IsIISServerImage(ctx.Root) {
			return true, ""
		}
		return false, "image is not an IIS web server (InetStp absent in SOFTWARE hive)"
	}
	if roles.IsIISServer() {
		return true, ""
	}
	return false, "target is not an IIS web server (InetStp registry key absent)"
}

// iisScriptExts are the server-executable extensions collected from web roots.
// A web shell is almost always one of these; static assets are left behind to
// keep the collection bounded. Matched case-insensitively.
var iisScriptExts = map[string]bool{
	".aspx": true, ".asmx": true, ".ashx": true, ".asax": true, ".ascx": true,
	".cshtml": true, ".asp": true, ".config": true,
	".php": true, ".php3": true, ".php4": true, ".php5": true, ".phtml": true,
	".jsp": true, ".jspx": true, ".pl": true, ".cgi": true,
}

// maxWebFileBytes caps an individual web-root file copy. Web shells are tiny;
// this keeps a stray large upload in a web root from bloating the case.
const maxWebFileBytes = 10 * 1024 * 1024

// discoveredSite records what the config parse resolved for one site, both for
// the collection logic and as an audit record written to iis_sites.json.
type discoveredSite struct {
	Name             string `json:"name"`
	ID               string `json:"id"`
	LogDirLive       string `json:"log_dir_live"`
	WebRootLive      string `json:"web_root_live"`
	LogFilesCopied   int    `json:"log_files_copied"`
	WebFilesCopied   int    `json:"web_files_copied"`
	WebFilesSkipped  int    `json:"web_files_skipped_oversize"`
}

func (m *IISCollection) Run(ctx *Context) Result {
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

	root := ctx.Root
	totalBytes := int64(0)

	// For a live case, read web-root payloads (potential web shells) off the VSS
	// shadow's raw clusters instead of through an ordinary OS open, so an
	// on-access AV/EDR cannot block or quarantine the read at the source. This is
	// the live counterpart to the dead-image ctx.Image path and uses the same
	// mechanism ntfs_metadata uses for $MFT (the shadow device path). If the raw
	// reader can't be opened, payload reads fall back to OS reads (readEvidenceBytes),
	// so collection still proceeds — just without the AV-safe guarantee. A dead-image
	// case already has ctx.Image and needs none of this.
	if ctx.Image == nil && ctx.Live && ctx.Shadow != nil && ctx.Shadow.ShadowPath != "" {
		if pr, err := NewRawVolumeReader(ctx.Shadow.ShadowPath); err == nil {
			ctx.PayloadReader = pr
			defer func() {
				pr.Close()
				ctx.PayloadReader = nil
			}()
		} else {
			result.AddWarning("payload-reader", fmt.Sprintf("raw shadow reader unavailable, web-root reads fall back to OS reads (on-access AV may interfere): %v", err))
		}
	}

	// 1. Copy the IIS configuration files. applicationHost.config is also the
	//    discovery source parsed below.
	configLive := `C:\Windows\System32\inetsrv\config`
	appHostLive := filepath.Join(configLive, "applicationHost.config")
	for _, cfg := range []string{"applicationHost.config", "redirection.config", "administration.config"} {
		srcLive := filepath.Join(configLive, cfg)
		rootSrc, err := mapToRoot(srcLive, root)
		if err != nil {
			continue
		}
		if _, statErr := os.Stat(rootSrc); statErr != nil {
			continue // sibling config not present on this box
		}
		dst := filepath.Join(ctx.OutputDir, cfg)
		if err := copyEvidenceFile(ctx, rootSrc, dst); err != nil {
			result.AddWarning(cfg, fmt.Sprintf("copy failed: %v", err))
			continue
		}
		if art, err := describeArtifact(dst); err == nil {
			result.Artifacts = append(result.Artifacts, art)
			totalBytes += art.Size
		}
	}

	// 2. Discover sites from applicationHost.config (falling back to defaults).
	sites := discoverIISSites(appHostLive, root, ctx.Live, &result)
	ctx.ReportProgress(0, len(sites)+1, totalBytes)

	// 3. Collect W3C logs and web-root scripts per site.
	logRoot := filepath.Join(ctx.OutputDir, "logs")

	// Payload-class web-root scripts are stored raw inside ONE per-module encrypted
	// container (architectural principle #9): the unmodified bytes are recoverable
	// by any third-party tool with the documented password, while the encrypted
	// form keeps a host AV/EDR from quarantining a collected web shell on write.
	// Non-payload W3C logs stay loose raw files (collected above / below).
	containerPath := filepath.Join(ctx.OutputDir, evidence.ContainerName)
	cw, cwErr := evidence.NewContainerWriter(containerPath)
	if cwErr != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("payload container: %v", cwErr))
	}

	for i := range sites {
		s := &sites[i]

		// 3a. Logs. Two candidates, into one per-site destination:
		//   - <logDir>\W3SVC<id> copied recursively — the standard per-site log
		//     tree.
		//   - <logDir> itself copied FLAT (top-level files only) — catches a
		//     central/flat W3C layout. It must not recurse, or it would pull
		//     every other site's W3SVC* tree into this site's folder.
		isLog := func(name string, _ int64) bool {
			return strings.HasSuffix(strings.ToLower(name), ".log")
		}
		dst := filepath.Join(logRoot, "W3SVC"+s.ID)
		for _, cand := range siteLogCandidates(s) {
			rootSrc, err := mapToRoot(cand.dir, root)
			if err != nil {
				continue
			}
			if info, statErr := os.Stat(rootSrc); statErr != nil || !info.IsDir() {
				continue
			}
			var n int
			var b int64
			var errs []error
			if cand.recurse {
				n, b, errs = collectFilteredTree(ctx, rootSrc, dst, isLog)
			} else {
				n, b, errs = collectFlatFiles(ctx, rootSrc, dst, isLog)
			}
			s.LogFilesCopied += n
			totalBytes += b
			for _, e := range errs {
				result.Errors = append(result.Errors, fmt.Sprintf("logs %s: %v", s.ID, e))
			}
		}

		// 3b. Web-root scripts: bounded by extension + per-file size cap; stored raw
		// inside the encrypted payload container under a per-site entry prefix.
		if cw != nil && s.WebRootLive != "" {
			rootSrc, err := mapToRoot(s.WebRootLive, root)
			if err == nil {
				if info, statErr := os.Stat(rootSrc); statErr == nil && info.IsDir() {
					n, b, errs := collectWebPayloads(ctx, rootSrc, s.ID, cw, func(name string, size int64) bool {
						if !iisScriptExts[strings.ToLower(filepath.Ext(name))] {
							return false
						}
						if size > maxWebFileBytes {
							s.WebFilesSkipped++
							return false
						}
						return true
					})
					s.WebFilesCopied += n
					totalBytes += b
					for _, e := range errs {
						result.Errors = append(result.Errors, fmt.Sprintf("web %s: %v", s.ID, e))
					}
				}
			}
		}

		result.BulkFiles += s.LogFilesCopied + s.WebFilesCopied
		ctx.ReportProgress(i+1, len(sites)+1, totalBytes)
	}

	// Finalize the payload container: keep it only if it holds at least one
	// web-shell candidate; a valid-but-empty archive would just be noise. The
	// stored entries are already counted in BulkFiles via WebFilesCopied above.
	if cw != nil {
		entries := cw.Count()
		if cerr := cw.Close(); cerr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("payload container close: %v", cerr))
		}
		if entries > 0 {
			if art, err := describeArtifact(containerPath); err == nil {
				result.Artifacts = append(result.Artifacts, art)
			}
		} else {
			os.Remove(containerPath)
		}
	}

	// 4. Also sweep http.sys error logs (attacks that never reached a site).
	httperrLive := `C:\Windows\System32\LogFiles\HTTPERR`
	if rootSrc, err := mapToRoot(httperrLive, root); err == nil {
		if info, statErr := os.Stat(rootSrc); statErr == nil && info.IsDir() {
			n, b, _ := collectFilteredTree(ctx, rootSrc, filepath.Join(logRoot, "HTTPERR"), func(name string, _ int64) bool {
				return strings.HasSuffix(strings.ToLower(name), ".log")
			})
			result.BulkFiles += n
			totalBytes += b
			if n > 0 {
				result.AddInfo("httperr", fmt.Sprintf("collected %d http.sys error log(s)", n))
			}
		}
	}
	ctx.ReportProgress(len(sites)+1, len(sites)+1, totalBytes)

	// 5. Write the discovery audit record.
	if data, err := json.MarshalIndent(sites, "", "  "); err == nil {
		recPath := filepath.Join(ctx.OutputDir, "iis_sites.json")
		if err := os.WriteFile(recPath, data, 0o644); err == nil {
			if art, err := describeArtifact(recPath); err == nil {
				result.Artifacts = append(result.Artifacts, art)
			}
		}
	}

	// Summaries.
	totalLogs, totalWeb := 0, 0
	for _, s := range sites {
		totalLogs += s.LogFilesCopied
		totalWeb += s.WebFilesCopied
	}
	result.AddInfo(m.Name(), fmt.Sprintf("discovered %d site(s); collected %d W3C log file(s) and %d web-root script file(s)",
		len(sites), totalLogs, totalWeb))
	if totalLogs == 0 {
		result.AddWarning(m.Name(), "no W3C log files collected — verify the configured log directory and that logging is enabled")
	}

	finalize(&result, started, ctx.Ctx)
	return result
}

// logCand is a candidate log directory and whether to walk it recursively.
type logCand struct {
	dir     string
	recurse bool
}

// siteLogCandidates returns where to look for a site's W3C logs: the per-site
// W3SVC<id> subfolder (recursive — the standard layout) and the configured
// directory itself scanned flat (for a central/flat layout, without recursing
// into and mixing in other sites' per-site trees).
func siteLogCandidates(s *discoveredSite) []logCand {
	if s.LogDirLive == "" {
		return nil
	}
	return []logCand{
		{dir: filepath.Join(s.LogDirLive, "W3SVC"+s.ID), recurse: true},
		{dir: s.LogDirLive, recurse: false},
	}
}

// appHostConfig is the minimal projection of applicationHost.config needed to
// resolve where each site logs and where its content lives. The XML package
// matches "system.applicationHost" as a literal element name.
type appHostConfig struct {
	System struct {
		Log struct {
			Central struct {
				Directory string `xml:"directory,attr"`
			} `xml:"centralW3CLogFile"`
		} `xml:"log"`
		Sites struct {
			SiteDefaults struct {
				LogFile struct {
					Directory string `xml:"directory,attr"`
				} `xml:"logFile"`
			} `xml:"siteDefaults"`
			Site []struct {
				Name    string `xml:"name,attr"`
				ID      string `xml:"id,attr"`
				LogFile struct {
					Directory string `xml:"directory,attr"`
				} `xml:"logFile"`
				Application []struct {
					Path             string `xml:"path,attr"`
					VirtualDirectory []struct {
						Path         string `xml:"path,attr"`
						PhysicalPath string `xml:"physicalPath,attr"`
					} `xml:"virtualDirectory"`
				} `xml:"application"`
			} `xml:"site"`
		} `xml:"sites"`
	} `xml:"system.applicationHost"`
}

// discoverIISSites parses applicationHost.config (read from the evidence root)
// and resolves each site's live log directory and web root, expanding %VAR%
// tokens. If the config can't be read or declares no sites, it returns a single
// default site so collection still attempts the standard locations.
func discoverIISSites(appHostLive, root string, live bool, result *Result) []discoveredSite {
	fallback := []discoveredSite{{
		Name:        "Default Web Site",
		ID:          "1",
		LogDirLive:  expandWinVars(`%SystemDrive%\inetpub\logs\LogFiles`, live),
		WebRootLive: expandWinVars(`%SystemDrive%\inetpub\wwwroot`, live),
	}}

	rootSrc, err := mapToRoot(appHostLive, root)
	if err != nil {
		result.AddWarning("discovery", fmt.Sprintf("applicationHost.config path map failed: %v; using defaults", err))
		return fallback
	}
	data, err := os.ReadFile(rootSrc)
	if err != nil {
		result.AddWarning("discovery", fmt.Sprintf("read applicationHost.config: %v; using defaults", err))
		return fallback
	}

	sites, ok := parseAppHostSites(data, live)
	if !ok {
		result.AddWarning("discovery", "parse applicationHost.config failed; using defaults")
		return fallback
	}
	if len(sites) == 0 {
		return fallback
	}
	return sites
}

// parseAppHostSites is the pure parse+resolve step of discovery, split out so it
// can be unit-tested against real applicationHost.config bytes without any shadow
// or filesystem. It unmarshals the config, resolves each site's log directory
// (per-site logFile, else siteDefaults, else central, else the standard default)
// and web root (the root application's root virtual directory), and expands
// %VAR% tokens to live paths. ok is false only when the XML itself won't parse.
func parseAppHostSites(data []byte, live bool) (sites []discoveredSite, ok bool) {
	var cfg appHostConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil, false
	}

	defaultLogDir := firstNonEmpty(
		cfg.System.Sites.SiteDefaults.LogFile.Directory,
		cfg.System.Log.Central.Directory,
		`%SystemDrive%\inetpub\logs\LogFiles`,
	)

	for _, s := range cfg.System.Sites.Site {
		logDir := firstNonEmpty(s.LogFile.Directory, defaultLogDir)
		webRoot := ""
		for _, app := range s.Application {
			if app.Path == "/" || app.Path == "" {
				for _, vd := range app.VirtualDirectory {
					if vd.Path == "/" || vd.Path == "" {
						webRoot = vd.PhysicalPath
						break
					}
				}
			}
			if webRoot != "" {
				break
			}
		}
		sites = append(sites, discoveredSite{
			Name:        s.Name,
			ID:          firstNonEmpty(s.ID, "0"),
			LogDirLive:  expandWinVars(logDir, live),
			WebRootLive: expandWinVars(webRoot, live),
		})
	}
	return sites, true
}

// expandWinVars expands %NAME% environment tokens in a path. Unknown tokens are
// left intact.
//
// When live is true (collecting on the running target) it resolves against the
// host environment. When live is false (a dead-image collection) it resolves the
// well-known Windows path variables from a fixed table instead of os.Getenv — the
// analyst's own machine is a DIFFERENT host than the image, so expanding an
// image-config path against the collector's environment is wrong. Only the drive
// letter differs from the image's real value, and mapToRoot strips the drive
// before rejoining the path under the image root, so a standard placeholder drive
// is correct.
func expandWinVars(s string, live bool) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "%")
		if i < 0 {
			b.WriteString(s)
			break
		}
		rest := s[i+1:]
		j := strings.Index(rest, "%")
		if j < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		name := rest[:j]
		if v := winVarValue(name, live); v != "" {
			b.WriteString(v)
		} else {
			b.WriteString("%" + name + "%")
		}
		s = rest[j+1:]
	}
	return b.String()
}

// imageDefaultEnv maps the well-known Windows path variables to their standard
// values, used for dead-image expansion so the result never depends on the
// analyst's own environment.
var imageDefaultEnv = map[string]string{
	"systemdrive":       `C:`,
	"systemroot":        `C:\Windows`,
	"windir":            `C:\Windows`,
	"programdata":       `C:\ProgramData`,
	"allusersprofile":   `C:\ProgramData`,
	"programfiles":      `C:\Program Files`,
	"programfiles(x86)": `C:\Program Files (x86)`,
	"public":            `C:\Users\Public`,
}

func winVarValue(name string, live bool) string {
	if live {
		return os.Getenv(name)
	}
	return imageDefaultEnv[strings.ToLower(name)]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// collectFlatFiles copies only the regular files directly in src (no recursion)
// for which keep returns true. Used for a flat/central log directory where
// recursing would pull in unrelated per-site subtrees.
func collectFlatFiles(ctx *Context, src, dst string, keep func(name string, size int64) bool) (int, int64, []error) {
	var count int
	var bytes int64
	var errs []error

	entries, err := os.ReadDir(src)
	if err != nil {
		return 0, 0, []error{fmt.Errorf("readdir %s: %v", src, err)}
	}
	for _, e := range entries {
		if ctx.Ctx.Err() != nil {
			errs = append(errs, fmt.Errorf("collect %s cancelled: %w", src, ctx.Ctx.Err()))
			return count, bytes, errs
		}
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if !keep(info.Name(), info.Size()) {
			continue
		}
		if err := os.MkdirAll(dst, 0o755); err != nil {
			errs = append(errs, fmt.Errorf("mkdir %s: %v", dst, err))
			return count, bytes, errs
		}
		if err := copyEvidenceFile(ctx, filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			errs = append(errs, fmt.Errorf("copy %s: %v", e.Name(), err))
			continue
		}
		count++
		bytes += info.Size()
	}
	return count, bytes, errs
}

// collectFilteredTree walks src and copies every regular file for which keep
// returns true into dst, preserving the relative directory structure. Returns
// the number of files copied, total bytes, and any per-file errors. Used for raw
// (non-payload) artifacts — W3C logs and http.sys error logs. Payload-class
// web-root scripts do NOT go through here; they are stored raw inside an
// encrypted container by collectWebPayloads.
func collectFilteredTree(ctx *Context, src, dst string, keep func(name string, size int64) bool) (int, int64, []error) {
	var count int
	var bytes int64
	var errs []error

	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if ctxErr := ctx.Ctx.Err(); ctxErr != nil {
			return ctxErr // stop promptly on cancellation / time-budget expiry
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("walk %s: %v", p, err))
			return nil
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		if !keep(info.Name(), info.Size()) {
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("rel %s: %v", p, err))
			return nil
		}
		dstPath := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			errs = append(errs, fmt.Errorf("mkdir %s: %v", filepath.Dir(dstPath), err))
			return nil
		}
		if cerr := copyEvidenceFile(ctx, p, dstPath); cerr != nil {
			errs = append(errs, fmt.Errorf("copy %s: %v", p, cerr))
			return nil
		}
		count++
		bytes += info.Size()
		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("walk %s: %v", src, err))
	}
	return count, bytes, errs
}

// collectWebPayloads walks src and stores every payload-class file for which keep
// returns true as a raw, unmodified entry inside the encrypted container cw. Each
// entry is named "<prefix>/<relative-path>" (forward-slash separated). The source
// bytes are read AV-safely (raw NTFS for an image) and written into the ZipCrypto
// archive, so a host AV/EDR cannot recognize and quarantine the collected web
// shell on write, while any third-party tool can still extract the exact original
// with the documented password (architectural principle #9). Returns the number
// of files stored, total bytes, and any per-file errors.
func collectWebPayloads(ctx *Context, src, prefix string, cw *evidence.ContainerWriter, keep func(name string, size int64) bool) (int, int64, []error) {
	var count int
	var bytes int64
	var errs []error

	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if ctxErr := ctx.Ctx.Err(); ctxErr != nil {
			return ctxErr // stop promptly on cancellation / time-budget expiry
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("walk %s: %v", p, err))
			return nil
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		if !keep(info.Name(), info.Size()) {
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("rel %s: %v", p, err))
			return nil
		}
		data, rerr := readEvidenceBytes(ctx, p)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("read %s: %v", p, rerr))
			return nil
		}
		entry := prefix + "/" + filepath.ToSlash(rel)
		if aerr := cw.Add(entry, data); aerr != nil {
			errs = append(errs, fmt.Errorf("store %s: %v", p, aerr))
			return nil
		}
		count++
		bytes += info.Size()
		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("walk %s: %v", src, err))
	}
	return count, bytes, errs
}
