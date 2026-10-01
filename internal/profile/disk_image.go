package profile

import (
	"github.com/Salahalza/SAFE/internal/module"
	"time"
)

// DiskImage is the profile for analyzing a dead disk image (E01/VHDX/raw)
// mounted read-only, instead of a live host. It is selected automatically when
// safe-collect is invoked with --source-root.
//
// A disk image is a static filesystem snapshot: it holds files and registry
// hives but NO volatile state — there is no running process list, no network
// table, no process memory (that evidence lives in a memory dump, not a disk
// image). So this profile deliberately contains only the file/hive-based
// collectors. The engine additionally skips any live-only module for an image
// source, so even if one were listed here it would be skipped; keeping the list
// image-only makes the intent explicit and the plan readout honest.
//
// Event logs are captured here by extended_event_channels, which copies the
// complete set of .evtx files straight off the image (the same channels
// eventlogs_core would export live, plus every application/role channel). The
// role collectors self-gate via Applies(), so this one profile serves a
// workstation image, a DC image, an IIS image, or an Exchange image alike.
//
// Class is ClassAny: the source is an image, and the imaged host could be either
// an endpoint or a server, so the class-based form defaulting does not apply.
func DiskImage() *Profile {
	return &Profile{
		Name:        "disk_image",
		Version:     "0.1.0",
		Description: "Dead disk image (E01/VHDX/raw, mounted read-only). File and registry-hive artifacts only — no volatile state exists in a disk image. Selected automatically with --source-root.",
		Class:       ClassAny,
		// The full winevt\Logs copy plus role logs (IIS/Exchange) can be large on
		// a server image; give generous headroom as with endpoint_deep/server_infra.
		TotalBudget: 60 * time.Minute,
		Modules: []module.Module{
			// System registry hives (SYSTEM/SOFTWARE/SAM/SECURITY), copied as files
			// from the image — feeds the shimcache/BAM/COM-hijack analyzers.
			&module.RegistryCore{},
			// NTFS metadata ($MFT, $LogFile, $UsnJrnl, $Secure, $Boot) parsed from
			// the image's raw volume via the shared raw-NTFS reader — the full
			// file-system timeline and USN activity journal.
			&module.NTFSMetadata{},
			// File/hive-based collectors, least-volatile on-disk artifacts. Every
			// one reads from the mounted image via ctx.Root.
			&module.AmcacheCollection{},
			&module.UserHivesCollection{},
			&module.PrefetchCollection{},
			&module.BrowserArtifacts{},
			&module.JumpLists{},
			// Full event-channel set as a direct file copy (covers the core 8 that
			// eventlogs_core exports live).
			&module.ExtendedEventChannels{},
			// Role-specific collectors. Each self-gates via Applies(); on an image
			// this uses offline hive detection so a DC/IIS/Exchange image is
			// classified from the image itself, not the analyst's host.
			&module.ADCollection{},
			&module.IISCollection{},
			&module.ExchangeCollection{},
		},
	}
}
