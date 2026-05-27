//go:build windows

package pathfinder

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

// listProfileSIDs enumerates the subkeys under ProfileList using the Windows
// registry API directly. Returns SIDs as clean UTF-8 strings regardless of
// system locale or console codepage.
func listProfileSIDs(profileListKey string) ([]string, error) {
	const subKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("open ProfileList: %w", err)
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("read subkey names: %w", err)
	}

	var sids []string
	for _, n := range names {
		if len(n) >= 2 && n[0] == 'S' && n[1] == '-' {
			sids = append(sids, n)
		}
	}
	return sids, nil
}

// readProfileImagePath reads the ProfileImagePath value for a given SID
// via the Windows registry API. Reads raw bytes and converts UTF-16 to UTF-8
// manually to avoid the GetStringValue path that can lose Unicode through
// ANSI codepage fallback on REG_EXPAND_SZ values.
//
// Returns the unexpanded form (with %SystemRoot% etc.) for caller to expand
// via expandWindowsEnvVars.
func readProfileImagePath(profileListKey, sid string) (string, error) {
	subKey := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\` + sid

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.READ)
	if err != nil {
		return "", fmt.Errorf("open subkey for %s: %w", sid, err)
	}
	defer k.Close()

	// GetValue returns the raw bytes and type code. We bypass GetStringValue
	// because its automatic REG_EXPAND_SZ handling has been observed to
	// corrupt non-ASCII characters via ANSI conversion.
	buf := make([]byte, 1024)
	n, valType, err := k.GetValue("ProfileImagePath", buf)
	if err == registry.ErrShortBuffer {
		// Resize and retry with the size GetValue told us we need.
		buf = make([]byte, n)
		n, valType, err = k.GetValue("ProfileImagePath", buf)
	}
	if err != nil {
		return "", fmt.Errorf("read ProfileImagePath for %s: %w", sid, err)
	}

	if valType != registry.SZ && valType != registry.EXPAND_SZ {
		return "", fmt.Errorf("ProfileImagePath has unexpected type %d", valType)
	}

	// The buffer contains UTF-16 little-endian. Decode it manually.
	s, err := decodeUTF16LE(buf[:n])
	if err != nil {
		return "", fmt.Errorf("decode UTF-16: %w", err)
	}

	return s, nil
}

// decodeUTF16LE converts a byte slice containing UTF-16 little-endian
// (the Windows registry's native string format) into a Go UTF-8 string.
// Trims trailing null terminators, which the registry API includes.
func decodeUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("UTF-16 buffer has odd length %d", len(b))
	}

	// Decode 2 bytes at a time into uint16.
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}

	// Trim trailing null terminators.
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}

	return string(utf16.Decode(u16)), nil
}
