// Package vss provides Volume Shadow Copy creation and management for reading
// files that Windows holds open with exclusive locks (registry hives, $MFT,
// browser databases, etc.).
//
// The package uses PowerShell + WMI for shadow creation because vssadmin's
// "create shadow" command is restricted to Windows Server (removed from
// client SKUs starting with Windows 8). WMI's Win32_ShadowCopy.Create()
// works on both client and server Windows and accesses the same underlying
// VSS service that the COM API would use directly.
//
// Usage:
//
//	shadow, err := vss.CreateShadow("C:")
//	if err != nil {
//	    // VSS unavailable — caller should fall back or report.
//	}
//	defer shadow.Cleanup()
//
//	src := filepath.Join(shadow.MountedPath, "Windows", "AppCompat", "Programs", "Amcache.hve")
//	// ... copy src to case folder
package vss

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Shadow represents an active Volume Shadow Copy and its symlink mount.
// Always call Cleanup() to release the shadow when done.
type Shadow struct {
	// ShadowID is the GUID of the shadow copy as reported by WMI.
	ShadowID string

	// ShadowPath is the raw shadow device path like:
	// \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42
	ShadowPath string

	// MountedPath is the symlink path readable as a normal directory,
	// e.g., C:\safe_shadow_<timestamp>
	MountedPath string

	// Volume is the volume the shadow was taken of, e.g., "C:".
	Volume string

	// CreatedAt is when the shadow was created.
	CreatedAt time.Time
}

// CreateShadow creates a Volume Shadow Copy of the specified volume and
// mounts it via symlink. The caller MUST call Cleanup() to release resources.
//
// Volume should be specified as "C:" (not "C:\" or "C").
func CreateShadow(volume string) (*Shadow, error) {
	return CreateShadowWithContext(context.Background(), volume)
}

// CreateShadowWithContext is the context-aware variant. The context bounds
// the time spent waiting for shadow creation, which can take 5-30 seconds
// on busy systems.
func CreateShadowWithContext(ctx context.Context, volume string) (*Shadow, error) {
	// Normalize volume to "C:" form (no trailing backslash).
	volume = strings.TrimSuffix(volume, `\`)
	if !strings.HasSuffix(volume, ":") {
		return nil, fmt.Errorf("volume must be specified as 'C:' (got %q)", volume)
	}

	// Pre-flight: ensure VSS service is operational.
	if err := checkVSSAvailable(ctx); err != nil {
		return nil, fmt.Errorf("VSS not available: %w", err)
	}

	createdAt := time.Now().UTC()

	// Create the shadow copy via PowerShell + WMI.
	// The script returns two lines: SHADOW_ID and DEVICE_OBJECT.
	psScript := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$class = [WMICLASS]'root\cimv2:Win32_ShadowCopy'
$result = $class.Create('%s\', 'ClientAccessible')
if ($result.ReturnValue -ne 0) {
    Write-Error "Win32_ShadowCopy.Create failed with code $($result.ReturnValue)"
    exit 1
}
# Emit the ID immediately: the shadow now exists, so if any later step fails the
# caller must still be able to recover this ID and delete the orphaned shadow.
Write-Output "SHADOW_ID=$($result.ShadowID)"
$shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
if (-not $shadow) {
    Write-Error "Created shadow not found in WMI"
    exit 1
}
Write-Output "DEVICE_OBJECT=$($shadow.DeviceObject)"
`, volume)

	cmd := exec.CommandContext(ctx, "powershell", "-STA", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, psErr := cmd.CombinedOutput()
	outStr := string(output)

	// Record the shadow ID in the durable ledger the instant we can see it —
	// WMI Create() has already made the shadow by the time the script prints
	// anything, so from here on the shadow may exist even if a later step fails.
	// The ledger is what makes a symlink-less orphan (a crash/failure before or
	// during mklink) discoverable by CleanupOrphans; without it, such a shadow
	// would be invisible and un-reclaimable, since discovery is symlink-based.
	createdID := extractShadowID(outStr)
	if createdID != "" {
		_ = recordShadowID(createdID)
	}

	// On any failure after creation, delete the orphaned shadow and drop it from
	// the ledger before returning.
	cleanupOnFailure := func() {
		if createdID != "" {
			_ = deleteShadow(context.Background(), createdID)
			unrecordShadowID(createdID)
		}
	}

	if psErr != nil {
		cleanupOnFailure()
		return nil, fmt.Errorf("PowerShell shadow creation failed: %w (output: %s)",
			psErr, strings.TrimSpace(outStr))
	}

	shadowID, shadowPath, err := parseShadowOutput(outStr)
	if err != nil {
		cleanupOnFailure()
		return nil, fmt.Errorf("parse PowerShell output: %w (raw: %s)",
			err, strings.TrimSpace(outStr))
	}

	shadow := &Shadow{
		ShadowID:   shadowID,
		ShadowPath: shadowPath,
		Volume:     volume,
		CreatedAt:  createdAt,
	}

	// Mount via symlink. The trailing backslash on the shadow path makes
	// mklink treat it as a directory link.
	mountPath := filepath.Join(`C:\`, fmt.Sprintf("safe_shadow_%s",
		createdAt.Format("20060102_150405")))

	mklinkCmd := exec.CommandContext(ctx, "cmd", "/c", "mklink", "/d",
		mountPath, shadowPath+`\`)
	mklinkOutput, err := mklinkCmd.CombinedOutput()
	if err != nil {
		cleanupOnFailure()
		return nil, fmt.Errorf("mklink failed: %w (output: %s)",
			err, strings.TrimSpace(string(mklinkOutput)))
	}

	shadow.MountedPath = mountPath
	return shadow, nil
}

// Cleanup removes the symlink and deletes the shadow copy.
// Safe to call multiple times.
func (s *Shadow) Cleanup() error {
	if s == nil {
		return nil
	}

	var errs []string

	// Remove the symlink first.
	if s.MountedPath != "" {
		rmCmd := exec.Command("cmd", "/c", "rmdir", s.MountedPath)
		if output, err := rmCmd.CombinedOutput(); err != nil {
			errs = append(errs, fmt.Sprintf("remove symlink: %v (%s)",
				err, strings.TrimSpace(string(output))))
		}
		s.MountedPath = ""
	}

	// Delete the shadow copy. Drop it from the ledger only on a clean delete; if
	// the delete fails the ID stays recorded so a later CleanupOrphans retries it.
	if s.ShadowID != "" {
		if err := deleteShadow(context.Background(), s.ShadowID); err != nil {
			errs = append(errs, fmt.Sprintf("delete shadow: %v", err))
		} else {
			unrecordShadowID(s.ShadowID)
		}
		s.ShadowID = ""
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// checkVSSAvailable verifies the VSS service is in a usable state.
func checkVSSAvailable(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sc", "query", "VSS")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc query VSS failed: %w", err)
	}

	out := string(output)
	if strings.Contains(out, "DISABLED") {
		return fmt.Errorf("VSS service is disabled on this system")
	}
	if !strings.Contains(out, "RUNNING") && !strings.Contains(out, "STOPPED") {
		return fmt.Errorf("VSS service is in an unexpected state: %s",
			strings.TrimSpace(out))
	}

	return nil
}

// deleteShadow removes a specific shadow copy by ID. vssadmin's "delete shadows"
// IS available on client Windows (only "create shadow" is restricted).
func deleteShadow(ctx context.Context, shadowID string) error {
	cmd := exec.CommandContext(ctx, "vssadmin", "delete", "shadows",
		"/shadow="+shadowID, "/quiet")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vssadmin delete shadows: %w (output: %s)",
			err, strings.TrimSpace(string(output)))
	}
	return nil
}

var shadowIDRegex = regexp.MustCompile(`SHADOW_ID=({[A-Fa-f0-9-]+})`)

// extractShadowID pulls just the shadow ID out of the PowerShell output, or ""
// if absent. Used on the failure paths where the full parse may not succeed but
// we still need the ID to clean up the already-created shadow.
func extractShadowID(output string) string {
	m := shadowIDRegex.FindStringSubmatch(output)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// parseShadowOutput extracts the shadow ID and device path from the
// PowerShell script's output.
func parseShadowOutput(output string) (id, path string, err error) {
	id = extractShadowID(output)
	if id == "" {
		return "", "", fmt.Errorf("could not find SHADOW_ID in output")
	}

	pathRegex := regexp.MustCompile(`DEVICE_OBJECT=(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)`)
	pathMatch := pathRegex.FindStringSubmatch(output)
	if len(pathMatch) < 2 {
		return "", "", fmt.Errorf("could not find DEVICE_OBJECT in output")
	}
	path = pathMatch[1]

	return id, path, nil
}

// ---- Shadow ledger --------------------------------------------------------
//
// SAFE records the ID of every shadow it creates in a small append-only ledger
// file, written the moment the shadow exists (before the symlink is made). This
// is what lets CleanupOrphans reclaim a shadow whose symlink was never created
// or was removed — a case the symlink glob alone can never find. It is
// deliberately NOT a blind "enumerate every Win32_ShadowCopy and delete": that
// would destroy the machine's restore points and other backup shadows, since a
// shadow carries no marker of who created it. Only IDs SAFE itself recorded are
// ever acted on.

// ledgerDir, when non-empty, overrides the ledger location (tests set this so
// they never touch the real machine-wide ledger).
var ledgerDir string

func ledgerPath() string {
	if ledgerDir != "" {
		return filepath.Join(ledgerDir, "shadows.ledger")
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "SAFE", "shadows.ledger")
}

// recordShadowID appends a shadow ID to the ledger (idempotent enough — duplicate
// lines are de-duplicated on read).
func recordShadowID(id string) error {
	p := ledgerPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(id + "\n")
	return err
}

// ledgerShadowIDs returns the distinct shadow IDs currently recorded.
func ledgerShadowIDs() []string {
	data, err := os.ReadFile(ledgerPath())
	if err != nil {
		return nil
	}
	var ids []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		id := strings.TrimSpace(line)
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// unrecordShadowID removes a shadow ID from the ledger. Removing the last entry
// deletes the ledger file.
func unrecordShadowID(id string) {
	var kept []string
	for _, x := range ledgerShadowIDs() {
		if x != id {
			kept = append(kept, x)
		}
	}
	p := ledgerPath()
	if len(kept) == 0 {
		_ = os.Remove(p)
		return
	}
	_ = os.WriteFile(p, []byte(strings.Join(kept, "\n")+"\n"), 0o644)
}

// shadowExists reports whether a shadow with the given ID is still present in WMI.
func shadowExists(id string) (bool, error) {
	psScript := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$s = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq '%s' }
if ($s) { Write-Output "EXISTS" }
`, id)
	cmd := exec.Command("powershell", "-STA", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("powershell query: %w (output: %s)",
			err, strings.TrimSpace(string(output)))
	}
	return strings.Contains(string(output), "EXISTS"), nil
}

// CleanupOrphans removes any SAFE-created shadows and symlinks left over
// from previous interrupted runs.
//
// SAFE shadows are identified by matching symlinks at C:\safe_shadow_*.
// For each such symlink found:
//   - Determine the shadow ID it points to (via symlink target)
//   - Delete the shadow
//   - Remove the symlink
//
// Returns the count of orphans cleaned up and any errors encountered.
// Errors during individual cleanup do not stop the overall operation;
// all errors are collected and returned.
func CleanupOrphans() (int, []error) {
	var errs []error
	cleaned := 0
	handled := map[string]bool{} // shadow IDs dealt with via the symlink pass

	// Pass 1 — symlink-tracked orphans: everything with a C:\safe_shadow_* link.
	matches, err := filepath.Glob(`C:\safe_shadow_*`)
	if err != nil {
		return 0, []error{fmt.Errorf("glob safe_shadow_* in C:\\: %w", err)}
	}

	for _, symlinkPath := range matches {
		// Resolve the symlink to get the shadow device path it points to.
		target, err := os.Readlink(symlinkPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("read symlink %s: %w", symlinkPath, err))
			// Try to remove the symlink anyway; if it's broken, this is best-effort.
			_ = removeSymlink(symlinkPath)
			continue
		}

		// Extract the shadow ID by querying VSS for shadows matching this device path.
		shadowID, err := findShadowIDByDevicePath(target)
		if err != nil {
			// Couldn't identify the shadow — but we can still remove the symlink.
			errs = append(errs, fmt.Errorf("find shadow for %s: %w", target, err))
			if rmErr := removeSymlink(symlinkPath); rmErr != nil {
				errs = append(errs, fmt.Errorf("remove orphan symlink %s: %w", symlinkPath, rmErr))
			}
			continue
		}

		// Delete the shadow.
		if shadowID != "" {
			handled[shadowID] = true
			if delErr := deleteShadow(context.Background(), shadowID); delErr != nil {
				errs = append(errs, fmt.Errorf("delete orphan shadow %s: %w", shadowID, delErr))
				// Continue — still try to remove the symlink.
			} else {
				unrecordShadowID(shadowID)
			}
		}

		// Remove the symlink.
		if rmErr := removeSymlink(symlinkPath); rmErr != nil {
			errs = append(errs, fmt.Errorf("remove symlink %s: %w", symlinkPath, rmErr))
			continue
		}

		cleaned++
	}

	// Pass 2 — symlink-less orphans: shadows SAFE recorded in the ledger but that
	// have no symlink (a crash/failure before or during mklink). These are
	// invisible to the glob above, so reclaim them here. Only ledger IDs are
	// touched — never a blind enumeration — so the machine's own restore points
	// and third-party backup shadows are left alone.
	for _, id := range ledgerShadowIDs() {
		if handled[id] {
			continue
		}
		exists, err := shadowExists(id)
		if err != nil {
			errs = append(errs, fmt.Errorf("check ledger shadow %s: %w", id, err))
			continue
		}
		if exists {
			if delErr := deleteShadow(context.Background(), id); delErr != nil {
				errs = append(errs, fmt.Errorf("delete ledger orphan shadow %s: %w", id, delErr))
				continue // keep it in the ledger to retry next time
			}
			cleaned++
		}
		// Whether it existed or was already gone, it is no longer outstanding.
		unrecordShadowID(id)
	}

	return cleaned, errs
}

// removeSymlink removes a directory symlink using cmd.exe rmdir.
func removeSymlink(path string) error {
	cmd := exec.Command("cmd", "/c", "rmdir", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rmdir failed: %v (output: %s)",
			err, strings.TrimSpace(string(output)))
	}
	return nil
}

// findShadowIDByDevicePath queries VSS for the shadow whose DeviceObject
// matches the given path. Returns empty string with nil error if no match.
func findShadowIDByDevicePath(devicePath string) (string, error) {
	// Strip trailing backslash if present (mklink adds it, WMI doesn't expect it).
	devicePath = strings.TrimSuffix(devicePath, `\`)

	psScript := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.DeviceObject -eq '%s' }
if ($shadow) {
    Write-Output $shadow.ID
}
`, devicePath)

	cmd := exec.Command("powershell", "-STA", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("powershell query: %w (output: %s)",
			err, strings.TrimSpace(string(output)))
	}

	id := strings.TrimSpace(string(output))
	return id, nil
}

// ListSAFEShadows returns information about SAFE-created shadows currently
// on the system (those with matching C:\safe_shadow_* symlinks). Useful
// for the --cleanup-shadows command to report what will be cleaned.
func ListSAFEShadows() ([]OrphanInfo, error) {
	matches, err := filepath.Glob(`C:\safe_shadow_*`)
	if err != nil {
		return nil, fmt.Errorf("glob safe_shadow_*: %w", err)
	}

	var infos []OrphanInfo
	seenID := map[string]bool{}
	for _, symlinkPath := range matches {
		info := OrphanInfo{SymlinkPath: symlinkPath}

		// Get symlink creation time as proxy for shadow age.
		if stat, err := os.Lstat(symlinkPath); err == nil {
			info.CreatedAt = stat.ModTime()
		}

		// Try to resolve to shadow target.
		if target, err := os.Readlink(symlinkPath); err == nil {
			info.ShadowPath = strings.TrimSuffix(target, `\`)
			if id, err := findShadowIDByDevicePath(info.ShadowPath); err == nil {
				info.ShadowID = id
			}
		}
		if info.ShadowID != "" {
			seenID[info.ShadowID] = true
		}
		infos = append(infos, info)
	}

	// Also report symlink-less orphans recorded in the ledger (a shadow whose
	// symlink was never created or was removed), so --cleanup-shadows shows what
	// pass 2 of CleanupOrphans will reclaim.
	for _, id := range ledgerShadowIDs() {
		if seenID[id] {
			continue
		}
		infos = append(infos, OrphanInfo{ShadowID: id})
	}

	return infos, nil
}

// OrphanInfo describes a SAFE-created shadow found on the system.
type OrphanInfo struct {
	SymlinkPath string    // C:\safe_shadow_<timestamp>
	ShadowPath  string    // \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
	ShadowID    string    // {guid}
	CreatedAt   time.Time // approximate creation time from symlink mtime
}
