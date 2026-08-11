package ts

import (
	"bytes"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

func TestMediaStreamFlushReturnsPendingSlots(t *testing.T) {
	const pid = 0x100
	sink := newOutputAligner(pid)
	stream := newMediaStream(
		pid,
		astits.StreamTypeH264Video,
		sink,
		&identityMediaTransformer{PESHandler: sink},
	)
	stream.sink.tokens = append(stream.sink.tokens, 0)

	completed, err := stream.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if len(completed) != 1 || completed[0].token != 0 || len(completed[0].packets) != 0 {
		t.Fatalf("completed slots = %+v, want one empty slot for token 0", completed)
	}
}

func TestOutputAlignerStampsPacketsOntoTokensInOrder(t *testing.T) {
	a := newOutputAligner(0x100)
	a.tokens = append(a.tokens, 0)
	completed := a.align()
	if len(completed) != 0 {
		t.Fatalf("align with no packets completed %d slots", len(completed))
	}

	a.tokens = append(a.tokens, 1)
	queueOutputAlignerPacket(t, a, 1)
	queueOutputAlignerPacket(t, a, 2)
	completed = a.align()
	flushed, err := a.flush()
	if err != nil {
		t.Fatal(err)
	}
	completed = append(completed, flushed...)

	if len(completed) != 2 {
		t.Fatalf("completed count = %d, want 2", len(completed))
	}
	if completed[0].token != 0 || completed[1].token != 1 {
		t.Fatalf("tokens = %d, %d, want 0, 1", completed[0].token, completed[1].token)
	}
	if completed[0].packets[0].Header.ContinuityCounter != 1 ||
		completed[1].packets[0].Header.ContinuityCounter != 2 {
		t.Fatal("packets not stamped onto their tokens in order")
	}
}

func TestOutputAlignerSpillsSurplusOntoLastToken(t *testing.T) {
	a := newOutputAligner(0x100)
	a.tokens = append(a.tokens, 0)
	queueOutputAlignerPacket(t, a, 1)
	queueOutputAlignerPacket(t, a, 2)
	completed := a.align()
	flushed, err := a.flush()
	if err != nil {
		t.Fatal(err)
	}
	completed = append(completed, flushed...)

	if len(completed) != 1 || completed[0].token != 0 {
		t.Fatalf("completed = %+v, want single slot for token 0", completed)
	}
	if len(completed[0].packets) != 2 {
		t.Fatalf("surplus packet not spilled onto last token: %d packets", len(completed[0].packets))
	}
}

func TestOutputAlignerPreservesDelayedSurplusPacket(t *testing.T) {
	a := newOutputAligner(0x100)
	a.tokens = append(a.tokens, 0)
	queueOutputAlignerPacket(t, a, 1)
	completed := a.align()

	queueOutputAlignerPacket(t, a, 2)
	flushed, err := a.flush()
	if err != nil {
		t.Fatal(err)
	}
	completed = append(completed, flushed...)

	if len(completed) != 1 || completed[0].token != 0 {
		t.Fatalf("completed = %+v, want single slot for token 0", completed)
	}
	if len(completed[0].packets) != 2 {
		t.Fatalf("delayed surplus packet was lost: %d packets", len(completed[0].packets))
	}
}

func TestOutputAlignerFlushCompletesLeftoverTokensEmpty(t *testing.T) {
	a := newOutputAligner(0x100)
	a.tokens = append(a.tokens, 0, 1)
	queueOutputAlignerPacket(t, a, 1)
	completed, err := a.flush()
	if err != nil {
		t.Fatal(err)
	}

	if len(completed) != 2 {
		t.Fatalf("completed count = %d, want 2", len(completed))
	}
	if completed[0].token != 0 || len(completed[0].packets) != 1 {
		t.Fatalf("first token should carry the only packet, got %+v", completed[0])
	}
	if completed[1].token != 1 || len(completed[1].packets) != 0 {
		t.Fatalf("leftover token should complete with no packets, got %+v", completed[1])
	}
	if len(a.tokens) != 0 {
		t.Fatalf("tokens remain after flush: %d", len(a.tokens))
	}
}

func TestOutputAlignerUsesRegeneratedCCForAdaptationOnlyPacket(t *testing.T) {
	const pid = 0x100
	payloadPacket := func(cc uint8) *astits.Packet {
		return &astits.Packet{Header: astits.PacketHeader{
			ContinuityCounter:         cc,
			HasPayload:                true,
			PayloadUnitStartIndicator: true,
			PID:                       pid,
		}}
	}
	pesHeader := []byte{
		0x00, 0x00, 0x01, 0xE0,
		0x00, 0x00,
		0x80, 0x00, 0x00,
	}

	a := newOutputAligner(pid)
	if err := a.registerInputPacket(0, payloadPacket(4)); err != nil {
		t.Fatal(err)
	}
	if err := a.PESHeader(pesHeader); err != nil {
		t.Fatal(err)
	}
	if err := a.PESPayload(bytes.Repeat([]byte{0x11}, 176)); err != nil {
		t.Fatal(err)
	}
	if err := a.PESEnd(); err != nil {
		t.Fatal(err)
	}

	if err := a.registerInputPacket(1, &astits.Packet{
		Header: astits.PacketHeader{
			ContinuityCounter:  4,
			HasAdaptationField: true,
			PID:                pid,
		},
		AdaptationField: &astits.PacketAdaptationField{
			HasPCR: true,
			PCR:    &astits.ClockReference{Base: 180_000},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.registerInputPacket(2, payloadPacket(5)); err != nil {
		t.Fatal(err)
	}
	if err := a.PESHeader(pesHeader); err != nil {
		t.Fatal(err)
	}
	if err := a.PESPayload([]byte{0x22}); err != nil {
		t.Fatal(err)
	}
	if err := a.PESEnd(); err != nil {
		t.Fatal(err)
	}

	completed, err := a.flush()
	if err != nil {
		t.Fatal(err)
	}
	var packets []*astits.Packet
	for _, slot := range completed {
		packets = append(packets, slot.packets...)
	}
	wantCC := []uint8{4, 5, 5, 6}
	if got, want := len(packets), len(wantCC); got != want {
		t.Fatalf("packet count = %d, want %d", got, want)
	}
	for i, packet := range packets {
		if packet.Header.ContinuityCounter != wantCC[i] {
			t.Fatalf(
				"packet %d continuity counter = %d, want %d",
				i,
				packet.Header.ContinuityCounter,
				wantCC[i],
			)
		}
	}
}

func queueOutputAlignerPacket(t *testing.T, a *outputAligner, cc uint8) {
	t.Helper()
	a.packetizer.SetContinuityCounter((cc + 1) & 0x0F)
	if err := a.packetizer.WriteAdaptationOnly(
		&astits.PacketAdaptationField{DiscontinuityIndicator: true},
	); err != nil {
		t.Fatal(err)
	}
}
