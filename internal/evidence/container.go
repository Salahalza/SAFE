// Container storage for payload-class artifacts (web-root scripts / web shells).
//
// This is the raw, third-party-readable replacement for the loss-free-but-opaque
// .qtn byte transform in codec.go. Instead of scrambling each collected payload
// into a SAFE-proprietary form, the collector stores the raw, byte-for-byte
// original files inside a single per-module ZipCrypto-encrypted archive. Two
// forensic invariants are met at once (architectural principle #9):
//
//   (a) byte-for-byte recoverable by ANY third-party tool — the archive is a
//       standard zip; the entries hold the unmodified source bytes; 7-Zip,
//       Info-ZIP unzip, WinRAR, and Python's stdlib zipfile all extract it with
//       the (public, documented) password; and
//   (b) not quarantinable by the host AV/EDR on write — an on-access scanner
//       cannot inspect the encrypted archive contents, so it does not recognize
//       the collected web shells and cannot quarantine the evidence.
//
// The password is NOT a secret and NOT a transform of the payload bytes: it is the
// long-standing malware-handling convention ("infected"), recorded in the case so
// any analyst can open the container. Encryption here protects already-collected
// evidence from the analyst's own AV — it does not hide anything from the analyst.
//
// This is defensive evidence preservation, exactly as in codec.go's header notice.
// Nothing is executed; the raw bytes are recoverable by anyone with the password.
package evidence

import (
	"fmt"
	"io"
	"os"

	"github.com/yeka/zip"
)

// ContainerPassword is the fixed, non-secret password on every payload container.
// It follows the standard malware-handling convention so any analyst — and any
// third-party archive tool — can extract the raw evidence. Its only job is to keep
// the host AV from scanning (and quarantining) the payloads inside the archive.
const ContainerPassword = "infected"

// ContainerName is the payload container filename written into an
// iis_collection module directory (alongside logs/ and the config).
const ContainerName = "web_payloads.zip"

// ContainerWriter accumulates payload-class artifacts into one ZipCrypto-encrypted
// zip. Each entry holds the raw, unmodified source bytes; the encrypted container
// form keeps a host AV/EDR from quarantining the evidence on write.
type ContainerWriter struct {
	f  *os.File
	zw *zip.Writer
	n  int
}

// NewContainerWriter creates (or truncates) the container file at path and
// prepares it for encrypted writes.
func NewContainerWriter(path string) (*ContainerWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &ContainerWriter{f: f, zw: zip.NewWriter(f)}, nil
}

// Add stores data as a ZipCrypto-encrypted entry named name (forward-slash
// separated, per the zip spec). The bytes are stored raw — no transform.
func (c *ContainerWriter) Add(name string, data []byte) error {
	w, err := c.zw.Encrypt(name, ContainerPassword, zip.StandardEncryption)
	if err != nil {
		return fmt.Errorf("create encrypted entry %s: %w", name, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write entry %s: %w", name, err)
	}
	c.n++
	return nil
}

// Count reports how many entries have been added.
func (c *ContainerWriter) Count() int { return c.n }

// Close flushes the central directory and closes the underlying file.
func (c *ContainerWriter) Close() error {
	zerr := c.zw.Close()
	ferr := c.f.Close()
	if zerr != nil {
		return zerr
	}
	return ferr
}

// ReadContainer opens the container at path and calls fn for each stored entry
// with its decrypted raw bytes (the byte-for-byte original file). Entry names are
// forward-slash separated.
func ReadContainer(path string, fn func(name string, data []byte) error) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.IsEncrypted() {
			f.SetPassword(ContainerPassword)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open entry %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("read entry %s: %w", f.Name, err)
		}
		if err := fn(f.Name, data); err != nil {
			return err
		}
	}
	return nil
}

// ReadContainerEntry returns the raw bytes of a single named entry, or
// os.ErrNotExist if the container has no such entry.
func ReadContainerEntry(path, name string) ([]byte, error) {
	var out []byte
	found := false
	if err := ReadContainer(path, func(n string, data []byte) error {
		if n == name {
			out = data
			found = true
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if !found {
		return nil, os.ErrNotExist
	}
	return out, nil
}

// ContainerExists reports whether a payload container is present at path.
func ContainerExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
