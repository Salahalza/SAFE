package roles

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"www.velocidex.com/golang/regparser"
)

// This file provides offline role detection: instead of probing the live host
// registry (roles_windows.go), it opens the registry hive FILES from a mounted
// disk image and reads the same marker keys. It reuses regparser — already a
// dependency for the lab-side hive analyzers — so it needs no new library and
// builds on every platform (the analyst runs this host-side over the image).
//
// The *Image functions take the read-only-mounted image volume root (ctx.Root),
// under which the OS hives live at Windows\System32\config\{SYSTEM,SOFTWARE}.

func systemHivePath(root string) string {
	return filepath.Join(root, "Windows", "System32", "config", "SYSTEM")
}

func softwareHivePath(root string) string {
	return filepath.Join(root, "Windows", "System32", "config", "SOFTWARE")
}

// openHive opens and parses a hive file. The caller must close the returned
// file. Errors (missing hive, unparsable bytes) are returned so a detector can
// treat them as "role absent".
func openHive(path string) (*regparser.Registry, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	reg, err := regparser.NewRegistry(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("parse hive %s: %w", path, err)
	}
	return reg, f, nil
}

// IsDomainControllerImage reports whether the SYSTEM hive under a mounted image
// shows the NTDS service parameters key — the same marker the live detector
// uses, present only on a promoted DC.
//
// An offline hive has no CurrentControlSet symlink, so the active control set is
// resolved from Select\Current (a host that has been through repair/rollback
// cycles can have an active set of ControlSet003 or higher). That set is probed
// first, with ControlSet001/002 as a fallback if Select is unreadable — the old
// code checked only 001/002, so a DC whose active set was ControlSet003+ was
// silently misclassified as not-a-DC and its NTDS.dit/SYSVOL were never collected.
func IsDomainControllerImage(root string) bool {
	reg, f, err := openHive(systemHivePath(root))
	if err != nil {
		return false
	}
	defer f.Close()

	seen := map[string]bool{}
	var sets []string
	if cur := selectedControlSet(reg); cur != "" {
		sets = append(sets, cur)
		seen[cur] = true
	}
	for _, cs := range []string{"ControlSet001", "ControlSet002"} {
		if !seen[cs] {
			sets = append(sets, cs)
		}
	}
	for _, cs := range sets {
		if reg.OpenKey(cs+`\Services\NTDS\Parameters`) != nil {
			return true
		}
	}
	return false
}

// selectedControlSet returns the active control set name ("ControlSetNNN") from
// the SYSTEM hive's Select\Current DWORD, or "" if it cannot be read.
func selectedControlSet(reg *regparser.Registry) string {
	k := reg.OpenKey("Select")
	if k == nil {
		return ""
	}
	for _, v := range k.Values() {
		if strings.EqualFold(v.ValueName(), "Current") {
			if n := v.ValueData().Uint64; n > 0 {
				return fmt.Sprintf("ControlSet%03d", n)
			}
			return ""
		}
	}
	return ""
}

// IsIISServerImage reports whether the SOFTWARE hive under a mounted image shows
// the InetStp (IIS) key.
func IsIISServerImage(root string) bool {
	reg, f, err := openHive(softwareHivePath(root))
	if err != nil {
		return false
	}
	defer f.Close()
	return reg.OpenKey(`Microsoft\InetStp`) != nil
}

// IsExchangeServerImage reports whether the SOFTWARE hive under a mounted image
// shows the Exchange 2013+ product key.
func IsExchangeServerImage(root string) bool {
	reg, f, err := openHive(softwareHivePath(root))
	if err != nil {
		return false
	}
	defer f.Close()
	return reg.OpenKey(`Microsoft\ExchangeServer\v15`) != nil
}

// ExchangeInstallPathImage returns the Exchange install root (MsiInstallPath)
// read from the SOFTWARE hive under a mounted image, or "" if absent. Mirrors
// the live ExchangeInstallPath for discovery-first collection off an image.
func ExchangeInstallPathImage(root string) string {
	reg, f, err := openHive(softwareHivePath(root))
	if err != nil {
		return ""
	}
	defer f.Close()
	k := reg.OpenKey(`Microsoft\ExchangeServer\v15\Setup`)
	if k == nil {
		return ""
	}
	for _, v := range k.Values() {
		if strings.EqualFold(v.ValueName(), "MsiInstallPath") {
			return strings.TrimRight(v.ValueData().String, "\x00")
		}
	}
	return ""
}
