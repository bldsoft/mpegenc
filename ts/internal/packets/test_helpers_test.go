package packets

import (
	"bytes"
	"context"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

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

	var buf bytes.Buffer
	mux := astits.NewMuxer(context.Background(), &buf)
	for _, stream := range streams {
		if err := mux.AddElementaryStream(astits.PMTElementaryStream{
			ElementaryPID: stream.pid,
			StreamType:    stream.streamType,
		}); err != nil {
			t.Fatalf("AddElementaryStream: %v", err)
		}
	}
	mux.SetPCRPID(streams[0].pid)

	pts := astits.ClockReference{Base: 90000}
	for _, pes := range pesPackets {
		if _, err := mux.WriteData(&astits.MuxerData{
			PID: pes.pid,
			PES: &astits.PESData{
				Data: pes.payload,
				Header: &astits.PESHeader{
					OptionalHeader: &astits.PESOptionalHeader{
						PTS:             &pts,
						PTSDTSIndicator: astits.PTSDTSIndicatorOnlyPTS,
					},
				},
			},
		}); err != nil {
			t.Fatalf("WriteData: %v", err)
		}
	}
	return buf.Bytes()
}

func adtsLikePayload(size int) []byte {
	frame := make([]byte, size)
	frame[0] = 0xFF
	frame[1] = 0xF1
	frame[2] = 0x50
	frame[3] = byte((size >> 11) & 0x03)
	frame[4] = byte((size >> 3) & 0xFF)
	frame[5] = byte((size&0x07)<<5) | 0x1F
	frame[6] = 0xFC
	return frame
}

func annexBSliceNAL(t *testing.T, size int) []byte {
	t.Helper()
	if size < 54 {
		t.Fatalf("annexBSliceNAL: need size >= 54, got %d", size)
	}
	nal := make([]byte, size)
	copy(nal, []byte{0x00, 0x00, 0x00, 0x01, 0x65})
	return nal
}
