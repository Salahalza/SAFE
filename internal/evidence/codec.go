// Package evidence provides quarantine-safe storage for collected files whose
// content a host antivirus/EDR would recognize and quarantine — chiefly the
// attacker payloads SAFE collects (web shells in a site root).
//
// Reading a flagged file off a mounted image is handled elsewhere by reading the
// raw NTFS volume (no file open for the scanner to gate). This package handles
// the OTHER touchpoint: WRITING the collected copy into the case folder, where
// on-access real-time protection scans the new file and can quarantine it right
// back out of the evidence. Storing the content under a reversible byte
// transform means the on-disk bytes match no signature, so no AV/EDR quarantines
// it — regardless of product, with no exclusions. The transform is symmetric and
// length-preserving; the lab-side reader decodes transparently. The true SHA-256
// of the original content is still recorded by the analyzer (e.g. web_files.csv)
// so threat-intel hash lookups are unaffected.
//
// This is defensive evidence preservation, not evasion: it protects already-
// collected forensic evidence on the analyst's own workstation from being
// destroyed by that workstation's own AV. Nothing is executed or hidden from the
// analyst.
package evidence

import "strings"

// EncodedSuffix marks a file stored under the quarantine-safe transform. It is
// appended after the original name (e.g. "shell.aspx" -> "shell.aspx.qtn") so
// the original extension is recoverable and the stored file is inert.
const EncodedSuffix = ".qtn"

// xorKey is the fixed transform key. A repeating multi-byte XOR is enough to
// make the stored bytes match no AV signature while staying trivially and
// losslessly reversible with random access. It is not a secret and not
// encryption — its only job is to keep a host AV from recognizing collected
// evidence on write.
var xorKey = []byte{
	0x53, 0x41, 0x46, 0x45, 0x2d, 0x71, 0x74, 0x6e,
	0xa7, 0x3c, 0xd9, 0x1e, 0x6b, 0xf0, 0x84, 0x2d,
}

// Transform applies the symmetric byte transform in place. Calling it once
// encodes plaintext; calling it again on the result decodes it. offset is the
// byte position of buf[0] within the whole file, so callers can transform a file
// in streamed chunks and get the same result as transforming it whole.
func Transform(buf []byte, offset int64) {
	k := len(xorKey)
	for i := range buf {
		buf[i] ^= xorKey[int((offset+int64(i))%int64(k))]
	}
}

// EncodedName returns the stored name for an original filename.
func EncodedName(name string) string { return name + EncodedSuffix }

// IsEncoded reports whether a stored name carries the quarantine-safe marker.
func IsEncoded(name string) bool { return strings.HasSuffix(name, EncodedSuffix) }

// OriginalName strips the quarantine-safe marker, returning the original name.
// A name without the marker is returned unchanged.
func OriginalName(name string) string {
	return strings.TrimSuffix(name, EncodedSuffix)
}
