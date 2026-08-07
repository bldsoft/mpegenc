package ts

import (
	"bytes"
	"io"
	"os"
	"testing"

	"mpegenc/sampleaes"
)

func FuzzEncryptMuxedTS(f *testing.F) {
	fixture, err := os.ReadFile("testdata/muxed.ts")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint32(0), []byte{}, false, uint32(0))
	f.Add(uint32(188), []byte{0}, false, uint32(0))
	f.Add(uint32(len(fixture)/2), []byte{0xFF}, true, uint32(len(fixture)-1))

	cfg := sampleaes.Config{
		Key: []byte("0123456789abcdef"),
		IV:  []byte("abcdef0123456789"),
	}
	f.Fuzz(func(t *testing.T, offset uint32, patch []byte, truncate bool, cut uint32) {
		input := append([]byte(nil), fixture...)
		if len(patch) > 188 {
			patch = patch[:188]
		}
		start := int(offset) % len(input)
		copy(input[start:], patch)
		if truncate {
			input = input[:int(cut)%(len(input)+1)]
		}
		_ = Encrypt(t.Context(), bytes.NewReader(input), io.Discard, cfg)
	})
}
