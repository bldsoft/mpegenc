package ts

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bldsoft/mpegenc/sampleaes"
)

func BenchmarkEncryptTS(b *testing.B) {
	fixtures, err := filepath.Glob("testdata/*.ts")
	if err != nil {
		b.Fatal(err)
	}
	if len(fixtures) == 0 {
		b.Fatal("no MPEG-TS fixtures found")
	}
	cfg := sampleaes.Config{
		Key: []byte("0123456789abcdef"),
		IV:  []byte("abcdef0123456789"),
	}

	for _, fixture := range fixtures {
		b.Run(strings.TrimSuffix(filepath.Base(fixture), filepath.Ext(fixture)), func(b *testing.B) {
			input, err := os.ReadFile(fixture)
			if err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(len(input)))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				if err := Encrypt(b.Context(), bytes.NewReader(input), io.Discard, cfg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
