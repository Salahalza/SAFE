// Package hashutil holds the one SHA-256 file hasher used across SAFE's
// integrity layers (collection manifest, analyzer output manifest, module
// artifact hashing). Keeping a single implementation means the collect-side and
// analyze-side hashes can never drift apart.
package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// SHA256File returns the lowercase hex SHA-256 digest of a file's contents,
// streamed so arbitrarily large artifacts never load fully into memory.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
