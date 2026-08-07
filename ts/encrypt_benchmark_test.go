package ts

import (
	"bytes"
	"io"
	"os"
	"testing"

	"mpegenc/sampleaes"
)

func BenchmarkEncryptMuxedTS(b *testing.B) {
	input, err := os.ReadFile("testdata/muxed.ts")
	if err != nil {
		b.Fatal(err)
	}
	cfg := sampleaes.Config{
		Key: []byte("0123456789abcdef"),
		IV:  []byte("abcdef0123456789"),
	}

	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := Encrypt(b.Context(), bytes.NewReader(input), io.Discard, cfg); err != nil {
			b.Fatal(err)
		}
	}
}
