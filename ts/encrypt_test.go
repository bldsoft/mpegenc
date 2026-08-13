package ts

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"

	"github.com/bldsoft/mpegenc/sampleaes"
)

const adtsHeaderSize = 7

func testKeyIV() (key, iv []byte) {
	key = make([]byte, 16)
	iv = make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)
	return key, iv
}

type tsStream struct {
	pid        uint16
	streamType astits.StreamType
}

type tsPES struct {
	pid     uint16
	payload []byte
}

func buildSyntheticTS(t *testing.T, streams []tsStream, pesPackets []tsPES) []byte {
	t.Helper()

	ctx := context.Background()
	var buf bytes.Buffer
	mux := astits.NewMuxer(ctx, &buf)

	for _, s := range streams {
		if err := mux.AddElementaryStream(astits.PMTElementaryStream{
			ElementaryPID: s.pid,
			StreamType:    s.streamType,
		}); err != nil {
			t.Fatalf("AddElementaryStream: %v", err)
		}
	}
	mux.SetPCRPID(streams[0].pid)

	pts := astits.ClockReference{Base: 90000}
	for _, p := range pesPackets {
		_, err := mux.WriteData(&astits.MuxerData{
			PID: p.pid,
			PES: &astits.PESData{
				Data: append([]byte(nil), p.payload...),
				Header: &astits.PESHeader{
					OptionalHeader: &astits.PESOptionalHeader{
						PTS:             &pts,
						PTSDTSIndicator: astits.PTSDTSIndicatorOnlyPTS,
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("WriteData: %v", err)
		}
	}
	return buf.Bytes()
}

func demuxPESPayloads(t *testing.T, r io.Reader) map[uint16][][]byte {
	t.Helper()
	ctx := context.Background()
	dmx := astits.NewDemuxer(ctx, r)
	out := make(map[uint16][][]byte)
	for {
		d, err := dmx.NextData()
		if err == astits.ErrNoMorePackets {
			break
		}
		if err != nil {
			t.Fatalf("demux: %v", err)
		}
		if d.PES != nil {
			out[d.PID] = append(out[d.PID], append([]byte(nil), d.PES.Data...))
		}
	}
	return out
}

func adtsLikePayload(size int) []byte {
	return buildADTSFrame(size)
}

func buildADTSFrame(totalSize int) []byte {
	if totalSize < adtsHeaderSize {
		panic("buildADTSFrame: size too small")
	}
	frame := make([]byte, totalSize)
	_, _ = rand.Read(frame[adtsHeaderSize:])
	frame[0] = 0xFF
	frame[1] = 0xF1 // MPEG-4, layer 0, protection_absent=1
	frame[2] = 0x50
	frame[3] = 0x80 | byte((totalSize>>11)&0x03)
	frame[4] = byte((totalSize >> 3) & 0xFF)
	frame[5] = byte((totalSize&0x07)<<5) | (frame[5] & 0x1F)
	frame[6] = 0xFC
	return frame
}

func annexBSliceNAL(t *testing.T, size int) []byte {
	t.Helper()
	nalPayload := size - 4 - 1
	if nalPayload < 49 {
		t.Fatalf("annexBSliceNAL: need size >= 54, got %d", size)
	}
	out := make([]byte, 0, size)
	out = append(out, 0x00, 0x00, 0x00, 0x01)
	out = append(out, 0x65)
	payload := make([]byte, nalPayload)
	_, _ = rand.Read(payload)
	out = append(out, payload...)
	return out
}

func assertPESRoundTrip(t *testing.T, original, processed map[uint16][][]byte) {
	t.Helper()
	if len(original) != len(processed) {
		t.Fatalf("PID count: got %d, want %d", len(processed), len(original))
	}
	for pid, origPayloads := range original {
		gotPayloads, ok := processed[pid]
		if !ok {
			t.Fatalf("missing PID 0x%04X in output", pid)
		}
		if len(gotPayloads) != len(origPayloads) {
			t.Fatalf("PID 0x%04X: %d PES packets, want %d", pid, len(gotPayloads), len(origPayloads))
		}
		for i := range origPayloads {
			if !bytes.Equal(origPayloads[i], gotPayloads[i]) {
				t.Fatalf("PID 0x%04X PES %d: payload mismatch", pid, i)
			}
		}
	}
}

func ac3LikePayload() []byte {
	frame := make([]byte, 128)
	_, _ = rand.Read(frame)
	frame[0] = 0x0B
	frame[1] = 0x77
	frame[4] = 0
	frame[5] = 8 << 3
	return frame
}

func TestAACEncryption(t *testing.T) {
	const audioPID = 0x101
	payload := adtsLikePayload(64)
	original := buildSyntheticTS(t, []tsStream{
		{pid: audioPID, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: audioPID, payload: payload}})

	key, iv := testKeyIV()
	var encrypted bytes.Buffer
	if err := Encrypt(t.Context(), bytes.NewReader(original), &encrypted, sampleaes.Config{Key: key, IV: iv}); err != nil {
		t.Fatal(err)
	}

	got := demuxPESPayloads(t, bytes.NewReader(encrypted.Bytes()))[audioPID][0]
	if !bytes.Equal(got[:23], payload[:23]) || !bytes.Equal(got[55:], payload[55:]) {
		t.Fatal("AAC clear bytes changed")
	}
	if bytes.Equal(got[23:55], payload[23:55]) {
		t.Fatal("AAC protected bytes unchanged")
	}
}

func TestAC3Encryption(t *testing.T) {
	const audioPID = 0x101
	payload := ac3LikePayload()
	original := buildSyntheticTS(t, []tsStream{
		{pid: audioPID, streamType: astits.StreamTypeAC3Audio},
	}, []tsPES{{pid: audioPID, payload: payload}})

	key, iv := testKeyIV()
	var encrypted bytes.Buffer
	if err := Encrypt(t.Context(), bytes.NewReader(original), &encrypted, sampleaes.Config{Key: key, IV: iv}); err != nil {
		t.Fatal(err)
	}

	got := demuxPESPayloads(t, bytes.NewReader(encrypted.Bytes()))[audioPID][0]
	if !bytes.Equal(got[:16], payload[:16]) {
		t.Fatal("AC-3 clear bytes changed")
	}
	if bytes.Equal(got[16:], payload[16:]) {
		t.Fatal("AC-3 protected bytes unchanged")
	}
}

func TestAACMultiFramePES(t *testing.T) {
	const audioPID = 0x101
	frame1 := buildADTSFrame(64)
	frame2 := buildADTSFrame(80)
	payload := append(append([]byte(nil), frame1...), frame2...)

	original := buildSyntheticTS(t, []tsStream{
		{pid: audioPID, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: audioPID, payload: payload}})

	key, iv := testKeyIV()
	var encrypted bytes.Buffer
	if err := Encrypt(t.Context(), bytes.NewReader(original), &encrypted, sampleaes.Config{Key: key, IV: iv}); err != nil {
		t.Fatal(err)
	}
	if encrypted.Len() < 193 {
		t.Fatalf("encrypted TS too short: %d bytes", encrypted.Len())
	}

	encPES := demuxPESPayloads(t, bytes.NewReader(encrypted.Bytes()))
	encPayload := encPES[audioPID][0]
	if bytes.Equal(encPayload[23:55], frame1[23:55]) || bytes.Equal(encPayload[64+23:64+71], frame2[23:71]) {
		t.Fatal("AAC frame protected bytes unchanged")
	}
}

func TestConfigValidation(t *testing.T) {
	const pid = 0x100
	original := buildSyntheticTS(t, []tsStream{
		{pid: pid, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: pid, payload: adtsLikePayload(64)}})

	cfg := sampleaes.Config{Key: make([]byte, 16), IV: make([]byte, 16)}
	cfg.Key[0] = 1
	cfg.IV[0] = 1

	err := Encrypt(t.Context(), bytes.NewReader(original), io.Discard, sampleaes.Config{Key: make([]byte, 15), IV: cfg.IV})
	if err == nil {
		t.Fatal("expected key length error")
	}

	err = Encrypt(t.Context(), bytes.NewReader(original), io.Discard, sampleaes.Config{Key: cfg.Key, IV: make([]byte, 15)})
	if err == nil {
		t.Fatal("expected iv length error")
	}

	err = decrypt(t.Context(), bytes.NewReader(original), io.Discard, sampleaes.Config{Key: make([]byte, 8), IV: cfg.IV})
	if err == nil {
		t.Fatal("expected decrypt key length error")
	}
}

func TestEncryptPreservesPESAndPacketCounts(t *testing.T) {
	input := buildSyntheticTS(t, []tsStream{
		{pid: 0x100, streamType: astits.StreamTypeH264Video},
	}, []tsPES{
		{pid: 0x100, payload: annexBSliceNAL(t, 256)},
	})

	key, iv := testKeyIV()
	var output bytes.Buffer
	if err := Encrypt(t.Context(), bytes.NewReader(input), &output, sampleaes.Config{Key: key, IV: iv}); err != nil {
		t.Fatal(err)
	}
	if got, want := output.Len(), len(input); got != want {
		t.Fatalf("encrypted remux size = %d, want %d", got, want)
	}
	originalPES := demuxPESPayloads(t, bytes.NewReader(input))
	remuxedPES := demuxPESPayloads(t, bytes.NewReader(output.Bytes()))
	if got, want := len(remuxedPES[0x100]), len(originalPES[0x100]); got != want {
		t.Fatalf("video PES count = %d, want %d", got, want)
	}
	if bytes.Equal(remuxedPES[0x100][0], originalPES[0x100][0]) {
		t.Fatal("video PES payload was not encrypted")
	}
}
