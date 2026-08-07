//go:build integration

package ts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"mpegenc/sampleaes"
)

func TestFFmpegCompatibility(t *testing.T) {
	fixtures, err := filepath.Glob("testdata/*.ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no MPEG-TS fixtures found")
	}
	sort.Strings(fixtures)

	key := []byte("0123456789012345")
	iv := []byte("0123456789012345")

	for _, fixture := range fixtures {
		t.Run(strings.TrimSuffix(filepath.Base(fixture), filepath.Ext(fixture)), func(t *testing.T) {
			probeOutput, err := exec.CommandContext(
				t.Context(),
				"ffprobe",
				"-v", "error",
				"-show_entries", "format=duration:stream=index,codec_name",
				"-of", "json",
				fixture,
			).CombinedOutput()
			if err != nil {
				t.Fatalf("ffprobe: %v: %s", err, probeOutput)
			}

			var media struct {
				Streams []struct {
					Index     int    `json:"index"`
					CodecName string `json:"codec_name"`
				} `json:"streams"`
				Format struct {
					Duration string `json:"duration"`
				} `json:"format"`
			}
			if err := json.Unmarshal(probeOutput, &media); err != nil {
				t.Fatal(err)
			}
			if len(media.Streams) == 0 {
				t.Fatal("no media streams found")
			}
			for _, stream := range media.Streams {
				if stream.CodecName != "h264" && stream.CodecName != "aac" {
					t.Fatalf("unsupported codec %q in stream %d", stream.CodecName, stream.Index)
				}
			}

			duration, err := strconv.ParseFloat(media.Format.Duration, 64)
			if err != nil {
				t.Fatalf("parse duration %q: %v", media.Format.Duration, err)
			}
			targetDuration := int(math.Ceil(duration))
			if targetDuration < 1 {
				targetDuration = 1
			}

			original, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			var encrypted bytes.Buffer
			if err := Encrypt(t.Context(), bytes.NewReader(original), &encrypted, sampleaes.Config{Key: key, IV: iv}); err != nil {
				t.Fatal(err)
			}

			tempDir := t.TempDir()
			encryptedPath := filepath.Join(tempDir, "encrypted.ts")
			if err := os.WriteFile(encryptedPath, encrypted.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tempDir, "key.bin"), key, 0o600); err != nil {
				t.Fatal(err)
			}
			playlistPath := filepath.Join(tempDir, "index.m3u8")
			playlist := fmt.Sprintf("#EXTM3U\n#EXT-X-VERSION:5\n#EXT-X-TARGETDURATION:%d\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"key.bin\",IV=0x%s\n#EXTINF:%s,\nencrypted.ts\n#EXT-X-ENDLIST\n", targetDuration, hex.EncodeToString(iv), media.Format.Duration)
			if err := os.WriteFile(playlistPath, []byte(playlist), 0o600); err != nil {
				t.Fatal(err)
			}

			for _, stream := range media.Streams {
				t.Run(fmt.Sprintf("%d-%s", stream.Index, stream.CodecName), func(t *testing.T) {
					inputs := [][]string{
						{"-i", fixture},
						{"-allowed_extensions", "ALL", "-i", playlistPath},
					}
					md5 := make([]string, len(inputs))
					for i, input := range inputs {
						args := []string{"-v", "error", "-xerror", "-nostdin"}
						args = append(args, input...)
						args = append(args, "-map", fmt.Sprintf("0:%d", stream.Index), "-f", "md5", "-")
						output, err := exec.CommandContext(t.Context(), "ffmpeg", args...).CombinedOutput()
						if err != nil {
							t.Fatalf("ffmpeg: %v: %s", err, output)
						}
						md5[i] = strings.TrimSpace(string(output))
					}
					if md5[0] != md5[1] {
						t.Errorf("decoded MD5: original %s, encrypted %s", md5[0], md5[1])
					}
				})
			}
		})
	}
}
