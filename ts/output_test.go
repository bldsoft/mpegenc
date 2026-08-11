package ts

import (
	"bytes"
	"context"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

func TestOutputAssemblerBlocksReadyLaterSlotUntilEarlierCommits(t *testing.T) {
	var output bytes.Buffer
	assembler := newOutputAssembler(astits.NewMuxer(context.Background(), &output))

	earlier := assembler.Reserve()
	later := assembler.Reserve()

	if err := assembler.Commit(completedSlot{
		token: later,
		packets: []*astits.Packet{
			testAssemblerPacket(0x101, 2, nil, []byte{0xA2}),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("wrote %d bytes while earlier slot is pending", output.Len())
	}

	if err := assembler.Commit(completedSlot{
		token: earlier,
		packets: []*astits.Packet{
			testAssemblerPacket(0x100, 1, nil, []byte{0xA1}),
		},
	}); err != nil {
		t.Fatal(err)
	}

	packets := demuxAssemblerPackets(t, output.Bytes())
	if got, want := len(packets), 2; got != want {
		t.Fatalf("packet count = %d, want %d", got, want)
	}
	if packets[0].Header.PID != 0x100 || len(packets[0].Payload) == 0 || packets[0].Payload[0] != 0xA1 {
		t.Fatalf("first drained packet = PID 0x%04X payload %v", packets[0].Header.PID, packets[0].Payload)
	}
	if packets[1].Header.PID != 0x101 || len(packets[1].Payload) == 0 || packets[1].Payload[0] != 0xA2 {
		t.Fatalf("second drained packet = PID 0x%04X payload %v", packets[1].Header.PID, packets[1].Payload)
	}
}

func TestOutputAssemblerEmptyCommitUnblocksLaterSlotsWithoutWriting(t *testing.T) {
	var output bytes.Buffer
	assembler := newOutputAssembler(astits.NewMuxer(context.Background(), &output))

	empty := assembler.Reserve()
	later := assembler.Reserve()

	if err := assembler.Commit(completedSlot{
		token: later,
		packets: []*astits.Packet{
			testAssemblerPacket(0x101, 2, nil, []byte{0xB2}),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := assembler.Commit(completedSlot{token: empty}); err != nil {
		t.Fatal(err)
	}

	packets := demuxAssemblerPackets(t, output.Bytes())
	if got, want := len(packets), 1; got != want {
		t.Fatalf("packet count = %d, want %d (empty slot must write nothing)", got, want)
	}
	if packets[0].Header.PID != 0x101 {
		t.Fatalf("drained PID = 0x%04X, want later media PID 0x0101", packets[0].Header.PID)
	}
	if len(packets[0].Payload) == 0 || packets[0].Payload[0] != 0xB2 {
		t.Fatalf("drained payload = %v, want [B2]", packets[0].Payload)
	}
}

func TestOutputAssemblerFlushRejectsUnresolvedSlots(t *testing.T) {
	assembler := newOutputAssembler(astits.NewMuxer(context.Background(), &bytes.Buffer{}))
	_ = assembler.Reserve()
	if err := assembler.Flush(); err == nil {
		t.Fatal("flush succeeded with unresolved slot")
	}
}

func demuxAssemblerPackets(t *testing.T, data []byte) []*astits.Packet {
	t.Helper()
	demuxer := astits.NewDemuxer(
		context.Background(),
		bytes.NewReader(data),
		astits.DemuxerOptPacketSize(astits.MpegTsPacketSize),
	)
	var packets []*astits.Packet
	for {
		packet, err := demuxer.NextPacket()
		if err == astits.ErrNoMorePackets {
			return packets
		}
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, packet)
	}
}

func testAssemblerPacket(
	pid uint16,
	cc uint8,
	adaptation *astits.PacketAdaptationField,
	payload []byte,
) *astits.Packet {
	return &astits.Packet{
		Header: astits.PacketHeader{
			ContinuityCounter:  cc,
			HasAdaptationField: adaptation != nil,
			HasPayload:         len(payload) > 0,
			PID:                pid,
		},
		AdaptationField: adaptation,
		Payload:         append([]byte(nil), payload...),
	}
}
