package module

import (
	"fmt"
	"io"
	"os"
	"strings"

	"www.velocidex.com/golang/go-ntfs/parser"
)

// ImageReader reads file content directly from a mounted disk image's raw NTFS
// volume, bypassing the operating-system filesystem API.
//
// Why this exists: on-access antivirus/EDR is a kernel file-system minifilter
// that intercepts file OPENS (IRP_MJ_CREATE). When a collected file matches a
// signature the open is denied with ERROR_VIRUS_INFECTED ("the file contains a
// virus…"), so a naive os.Open() of a web shell on a compromised image fails and
// the evidence is lost. Reading the volume's clusters directly is block I/O —
// no per-file open is issued, so there is nothing for the scanner to gate. This
// is the standard forensic-acquisition technique (Velociraptor's ntfs accessor,
// every disk imager) and is AV/EDR-agnostic: it does not depend on excluding a
// path from one specific product. It mirrors how ntfs_metadata.go reads $MFT
// from the raw VSS shadow device.
//
// Both evidence sources use this same block-I/O read: a dead-image case opens the
// mounted image volume by drive letter (NewImageReader), and a LIVE case opens the
// VSS shadow device by its raw path (NewRawVolumeReader over ctx.Shadow.ShadowPath)
// — see readEvidenceBytes. Reading a live web-root payload off the shadow's
// clusters is what makes live collection AV-safe by construction: it does not rely
// on the earlier assumption that an on-access scanner would let a read from the
// shadow through (it can and does re-scan on IRP_MJ_CREATE by content, shadow or
// not). Block I/O issues no per-file open, so there is nothing for the scanner to
// gate on either source.
type ImageReader struct {
	volume  string // e.g. "F:" — drive letter of the mounted image; "" for a shadow device
	device  *os.File
	ntfsCtx *parser.NTFSContext
}

// openRawNTFS opens a raw block device and parses its NTFS at offset 0. devicePath
// is anything the OS exposes as a raw volume/device: a mounted image volume
// (\\.\F:) or a VSS shadow (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN).
// Windows raw handles require sector-aligned reads, which PagedReader provides.
func openRawNTFS(devicePath string) (*os.File, *parser.NTFSContext, error) {
	fd, err := os.Open(devicePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open raw device %s: %w", devicePath, err)
	}
	pr, err := parser.NewPagedReader(fd, 1024*1024, 100)
	if err != nil {
		fd.Close()
		return nil, nil, fmt.Errorf("paged reader for %s: %w", devicePath, err)
	}
	ntfsCtx, err := parser.GetNTFSContext(pr, 0)
	if err != nil {
		fd.Close()
		return nil, nil, fmt.Errorf("parse NTFS on %s: %w", devicePath, err)
	}
	return fd, ntfsCtx, nil
}

// NewImageReader opens the raw volume device behind a mounted image root and
// parses its NTFS. root must be a drive-letter root such as "F:\". It returns an
// error if root is not a drive-letter volume or the volume cannot be parsed; the
// caller then falls back to OS reads (and on-access AV may interfere).
func NewImageReader(root string) (*ImageReader, error) {
	vol := driveLetterOf(root)
	if vol == "" {
		return nil, fmt.Errorf("source root %q is not a drive-letter volume; raw-NTFS read unavailable", root)
	}
	// \\.\F: opens the mounted volume as a raw device. NTFS starts at offset 0.
	fd, ntfsCtx, err := openRawNTFS(`\\.\` + vol)
	if err != nil {
		return nil, err
	}
	return &ImageReader{volume: vol, device: fd, ntfsCtx: ntfsCtx}, nil
}

// NewRawVolumeReader opens an arbitrary raw NTFS device — used for a live case's
// VSS shadow (ctx.Shadow.ShadowPath), which is exposed only as a device path, not
// a mounted drive letter. Content is then read by volume-relative path
// (readAllRel), off the shadow's clusters, so an on-access AV/EDR cannot block or
// quarantine the read of a live web shell. Mirrors how ntfs_metadata reads $MFT
// from the same shadow device.
func NewRawVolumeReader(devicePath string) (*ImageReader, error) {
	fd, ntfsCtx, err := openRawNTFS(devicePath)
	if err != nil {
		return nil, err
	}
	return &ImageReader{device: fd, ntfsCtx: ntfsCtx}, nil
}

// Volume returns the drive letter (e.g. "F:") this reader parses.
func (r *ImageReader) Volume() string { return r.volume }

// Close releases the raw volume handle.
func (r *ImageReader) Close() error {
	if r != nil && r.device != nil {
		return r.device.Close()
	}
	return nil
}

// copyFile writes the content of the file at src (a full path under the image
// root, e.g. "F:\\inetpub\\wwwroot\\shell.aspx") to dst, reading it via raw NTFS
// so on-access AV cannot block the read.
func (r *ImageReader) copyFile(src, dst string) error {
	rel := volumeRelativePath(src)
	if rel == "" {
		return fmt.Errorf("cannot derive volume-relative path from %q", src)
	}
	readerAt, err := parser.GetDataForPath(r.ntfsCtx, rel)
	if err != nil {
		return fmt.Errorf("raw NTFS open %s: %w", rel, err)
	}
	size := parser.RangeSize(readerAt)

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, io.NewSectionReader(readerAt, 0, size)); err != nil {
		return fmt.Errorf("copy bytes: %w", err)
	}
	return out.Sync()
}

// readAll reads a file's full content via raw NTFS from a drive-letter path
// (e.g. "F:\inetpub\wwwroot\shell.aspx" on a mounted image). Used for the small,
// bounded payload files (web-root scripts) where reading into memory is fine.
func (r *ImageReader) readAll(src string) ([]byte, error) {
	rel := volumeRelativePath(src)
	if rel == "" {
		return nil, fmt.Errorf("cannot derive volume-relative path from %q", src)
	}
	return r.readAllRel(rel)
}

// readAllRel reads a file's full content via raw NTFS by its volume-root-relative
// path (e.g. "\inetpub\wwwroot\shell.aspx"). This is the form used for a live VSS
// shadow, where the source has no drive letter of its own — the caller derives the
// path relative to the shadow root (ctx.Root).
func (r *ImageReader) readAllRel(rel string) ([]byte, error) {
	readerAt, err := parser.GetDataForPath(r.ntfsCtx, rel)
	if err != nil {
		return nil, fmt.Errorf("raw NTFS open %s: %w", rel, err)
	}
	size := parser.RangeSize(readerAt)
	buf := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(readerAt, 0, size), buf); err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	return buf, nil
}

// driveLetterOf returns "F:" for a root like "F:\", "f:\", or "F:", else "".
func driveLetterOf(root string) string {
	if len(root) >= 2 && root[1] == ':' &&
		((root[0] >= 'A' && root[0] <= 'Z') || (root[0] >= 'a' && root[0] <= 'z')) {
		return strings.ToUpper(root[:2])
	}
	return ""
}

// volumeRelativePath converts a drive-letter path like "F:\dir\file" to the
// volume-root-relative "\dir\file" form go-ntfs GetDataForPath expects. Returns
// "" if the input is not a drive-letter path.
func volumeRelativePath(full string) string {
	if len(full) < 2 || full[1] != ':' {
		return ""
	}
	rel := full[2:]
	if rel == "" {
		return `\`
	}
	if rel[0] != '\\' && rel[0] != '/' {
		rel = `\` + rel
	}
	return rel
}
