package evidence

import (
	"bytes"
	"testing"
)

// TestTransformRoundTripAllBytes proves the legacy .qtn transform is losslessly
// reversible for every byte value — applying it twice returns the original — and
// that it actually changes the bytes (so a host AV can't recognize the stored
// evidence). This is the only integrity guard on pre-container-migration
// web-shell evidence, which can no longer be re-collected, so it must not regress.
func TestTransformRoundTripAllBytes(t *testing.T) {
	orig := make([]byte, 256)
	for i := range orig {
		orig[i] = byte(i)
	}
	buf := append([]byte(nil), orig...)

	Transform(buf, 0) // encode
	if bytes.Equal(buf, orig) {
		t.Fatal("transform did not change the bytes; stored evidence would match its AV signature")
	}
	Transform(buf, 0) // decode
	if !bytes.Equal(buf, orig) {
		t.Fatal("transform is not self-inverse: decoded bytes differ from original")
	}
}

// TestTransformChunkedMatchesWhole proves the offset arithmetic: transforming a
// file in arbitrary streamed chunks (each at its true file offset) yields exactly
// the same result as transforming the whole buffer at once. The streaming decode
// path depends on this, and it's exactly where an off-by-one in the offset would
// silently corrupt recovered evidence.
func TestTransformChunkedMatchesWhole(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte((i*7 + 3) % 256)
	}

	whole := append([]byte(nil), data...)
	Transform(whole, 0)

	// Chunk boundaries deliberately not aligned to the 16-byte key length.
	chunked := append([]byte(nil), data...)
	bounds := []int{0, 30, 73, 128, 200}
	for i := 0; i+1 < len(bounds); i++ {
		start, end := bounds[i], bounds[i+1]
		Transform(chunked[start:end], int64(start))
	}

	if !bytes.Equal(whole, chunked) {
		t.Fatal("chunked transform differs from whole-buffer transform; offset handling is broken")
	}
}

func TestNameHelpers(t *testing.T) {
	if got := EncodedName("shell.aspx"); got != "shell.aspx.qtn" {
		t.Errorf("EncodedName = %q", got)
	}
	if !IsEncoded("shell.aspx.qtn") || IsEncoded("shell.aspx") {
		t.Error("IsEncoded misclassified a name")
	}
	if got := OriginalName("shell.aspx.qtn"); got != "shell.aspx" {
		t.Errorf("OriginalName = %q", got)
	}
	if got := OriginalName("plain.txt"); got != "plain.txt" {
		t.Errorf("OriginalName of non-encoded name should be unchanged, got %q", got)
	}
}
