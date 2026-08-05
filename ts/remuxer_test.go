package ts

import (
	"bytes"
	"context"
	"testing"

	"mpegenc/internal/go-astits"

	"mpegenc/sampleaes"
	"mpegenc/ts/codecs/avc"
	"mpegenc/ts/internal/mux"
	"mpegenc/ts/internal/pmtsignal"
	"mpegenc/ts/packets"
)

type identityMediaTransformer struct {
	packets.PESHandler
}

func (*identityMediaTransformer) Flush() error {
	return nil
}

type noopBlockCryptor struct{}

func (noopBlockCryptor) Reset() error {
	return nil
}

func (noopBlockCryptor) CryptBlocks([]byte) error {
	return nil
}

func newAVCTransformer(
	t *testing.T,
	next packets.PESHandler,
	block sampleaes.BlockCryptor,
) *avc.Transformer {
	t.Helper()
	transformer, err := avc.NewTransformer(
		next,
		block,
		func(pmtsignal.Patch) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	return transformer
}

func commitCompletedSlots(
	t *testing.T,
	assembler *outputAssembler,
	completed []completedSlot,
) {
	t.Helper()
	for _, slot := range completed {
		if err := assembler.Commit(slot); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMediaStreamCarriesPCROntoRegeneratedPacket(t *testing.T) {
	const pid = 0x100

	esPayload := append(
		[]byte{0x00, 0x00, 0x01, 0x67},
		bytes.Repeat([]byte{0xCD}, 16)...,
	)
	pesHeader := []byte{
		0x00, 0x00, 0x01, 0xE0,
		0x00, byte(3 + len(esPayload)),
		0x80, 0x00, 0x00,
	}
	pcr := &astits.ClockReference{Base: 90_000, Extension: 17}
	input := &astits.Packet{
		Header: astits.PacketHeader{
			ContinuityCounter:         9,
			HasAdaptationField:        true,
			HasPayload:                true,
			PayloadUnitStartIndicator: true,
			PID:                       pid,
		},
		AdaptationField: &astits.PacketAdaptationField{
			HasPCR: true,
			PCR:    pcr,
		},
		Payload: append(append([]byte(nil), pesHeader...), esPayload...),
	}

	var output bytes.Buffer
	assembler := newOutputAssembler(astits.NewMuxer(context.Background(), &output))
	sink := newOutputAligner(pid)
	stream := newMediaStream(
		pid,
		astits.StreamTypeH264Video,
		sink,
		newAVCTransformer(t, sink, noopBlockCryptor{}),
	)
	token := assembler.Reserve()
	completed, err := stream.Consume(token, input)
	if err != nil {
		t.Fatal(err)
	}
	commitCompletedSlots(t, assembler, completed)
	completed, err = stream.Flush()
	if err != nil {
		t.Fatal(err)
	}
	commitCompletedSlots(t, assembler, completed)
	if err := assembler.Flush(); err != nil {
		t.Fatal(err)
	}

	dmx := astits.NewDemuxer(
		context.Background(),
		bytes.NewReader(output.Bytes()),
		astits.DemuxerOptPacketSize(astits.MpegTsPacketSize),
	)
	packet, err := dmx.NextPacket()
	if err != nil {
		t.Fatal(err)
	}
	if packet.AdaptationField == nil || !packet.AdaptationField.HasPCR {
		t.Fatal("regenerated packet lost PCR")
	}
	if got := packet.AdaptationField.PCR; got.Base != pcr.Base || got.Extension != pcr.Extension {
		t.Fatalf("PCR = %+v, want %+v", got, pcr)
	}
	wantPayload := append([]byte(nil), input.Payload...)
	wantPayload[4], wantPayload[5] = 0, 0
	if !bytes.Equal(packet.Payload, wantPayload) {
		t.Fatal("regenerated PES bytes differ from input")
	}
}

func TestMediaStreamKeepsPCROnSeparateAdaptationOnlyPacket(t *testing.T) {
	const pid = 0x100

	pcr := &astits.ClockReference{Base: 180_000, Extension: 23}
	pcrPacket := &astits.Packet{
		Header: astits.PacketHeader{
			ContinuityCounter:  7,
			HasAdaptationField: true,
			PID:                pid,
		},
		AdaptationField: &astits.PacketAdaptationField{
			HasPCR: true,
			PCR:    pcr,
		},
	}
	esPayload := append(
		[]byte{0x00, 0x00, 0x01, 0x67},
		bytes.Repeat([]byte{0xEF}, 16)...,
	)
	pesPacket := &astits.Packet{
		Header: astits.PacketHeader{
			ContinuityCounter:         8,
			HasPayload:                true,
			PayloadUnitStartIndicator: true,
			PID:                       pid,
		},
		Payload: append([]byte{
			0x00, 0x00, 0x01, 0xE0,
			0x00, byte(3 + len(esPayload)),
			0x80, 0x00, 0x00,
		}, esPayload...),
	}

	var output bytes.Buffer
	assembler := newOutputAssembler(astits.NewMuxer(context.Background(), &output))
	sink := newOutputAligner(pid)
	stream := newMediaStream(
		pid,
		astits.StreamTypeH264Video,
		sink,
		newAVCTransformer(t, sink, noopBlockCryptor{}),
	)
	pcrToken := assembler.Reserve()
	completed, err := stream.Consume(pcrToken, pcrPacket)
	if err != nil {
		t.Fatal(err)
	}
	commitCompletedSlots(t, assembler, completed)
	pesToken := assembler.Reserve()
	completed, err = stream.Consume(pesToken, pesPacket)
	if err != nil {
		t.Fatal(err)
	}
	commitCompletedSlots(t, assembler, completed)
	completed, err = stream.Flush()
	if err != nil {
		t.Fatal(err)
	}
	commitCompletedSlots(t, assembler, completed)
	if err := assembler.Flush(); err != nil {
		t.Fatal(err)
	}

	if got, want := output.Len(), 2*astits.MpegTsPacketSize; got != want {
		t.Fatalf("output size = %d, want %d", got, want)
	}
	dmx := astits.NewDemuxer(
		context.Background(),
		bytes.NewReader(output.Bytes()),
		astits.DemuxerOptPacketSize(astits.MpegTsPacketSize),
	)
	gotPCR, err := dmx.NextPacket()
	if err != nil {
		t.Fatal(err)
	}
	if gotPCR.Header.HasPayload {
		t.Fatal("PCR-only input became a payload packet")
	}
	if gotPCR.Header.ContinuityCounter != pcrPacket.Header.ContinuityCounter {
		t.Fatalf(
			"PCR packet continuity counter = %d, want %d",
			gotPCR.Header.ContinuityCounter,
			pcrPacket.Header.ContinuityCounter,
		)
	}
	if gotPCR.AdaptationField == nil || !gotPCR.AdaptationField.HasPCR {
		t.Fatal("PCR-only output lost PCR")
	}

	gotPES, err := dmx.NextPacket()
	if err != nil {
		t.Fatal(err)
	}
	wantPayload := append([]byte(nil), pesPacket.Payload...)
	wantPayload[4], wantPayload[5] = 0, 0
	if !bytes.Equal(gotPES.Payload, wantPayload) {
		t.Fatal("regenerated PES bytes differ from input")
	}
}

func TestRemuxerRegeneratesCCForAdaptationOnlyPacketBetweenPES(t *testing.T) {
	const pid = 0x100

	var output bytes.Buffer
	remuxer := newRemuxer(
		astits.NewMuxer(context.Background(), &output),
		false,
		sampleaes.Config{},
	)
	sink := newOutputAligner(pid)
	sink.ccInitialized = true
	sink.packetizer.SetContinuityCounter(6)
	remuxer.streams = map[uint16]*mediaStream{
		pid: newMediaStream(
			pid,
			astits.StreamTypeH264Video,
			sink,
			&identityMediaTransformer{PESHandler: sink},
		),
	}

	if err := remuxer.Consume(&astits.Packet{
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
	if err := remuxer.Flush(); err != nil {
		t.Fatal(err)
	}

	packets := demuxAssemblerPackets(t, output.Bytes())
	if got, want := len(packets), 1; got != want {
		t.Fatalf("packet count = %d, want %d", got, want)
	}
	if got, want := packets[0].Header.ContinuityCounter, uint8(5); got != want {
		t.Fatalf("adaptation-only CC = %d, want %d", got, want)
	}
}

func TestRemuxerKeepsNewPUSIMetadataWithNewPES(t *testing.T) {
	const pid = 0x100

	pesHeader := []byte{
		0x00, 0x00, 0x01, 0xE0,
		0x00, 0x00,
		0x80, 0x00, 0x00,
	}
	newPacket := func(cc uint8, marker byte, pcr *astits.ClockReference) *astits.Packet {
		packet := &astits.Packet{
			Header: astits.PacketHeader{
				ContinuityCounter:         cc,
				HasPayload:                true,
				PayloadUnitStartIndicator: true,
				PID:                       pid,
			},
			Payload: append(append([]byte(nil), pesHeader...), marker),
		}
		if pcr != nil {
			packet.Header.HasAdaptationField = true
			packet.AdaptationField = &astits.PacketAdaptationField{
				HasPCR: true,
				PCR:    pcr,
			}
		}
		return packet
	}

	first := newPacket(4, 0x11, nil)
	pcr := &astits.ClockReference{Base: 270_000, Extension: 31}
	second := newPacket(5, 0x22, pcr)

	var output bytes.Buffer
	remuxer := newRemuxer(
		astits.NewMuxer(context.Background(), &output),
		false,
		sampleaes.Config{},
	)
	sink := newOutputAligner(pid)
	remuxer.streams = map[uint16]*mediaStream{
		pid: newMediaStream(
			pid,
			astits.StreamTypeH264Video,
			sink,
			&identityMediaTransformer{PESHandler: sink},
		),
	}
	if err := remuxer.Consume(first); err != nil {
		t.Fatal(err)
	}
	if err := remuxer.Consume(second); err != nil {
		t.Fatal(err)
	}
	if err := remuxer.Flush(); err != nil {
		t.Fatal(err)
	}

	if got, want := output.Len(), 2*astits.MpegTsPacketSize; got != want {
		t.Fatalf("output size = %d, want %d", got, want)
	}
	dmx := astits.NewDemuxer(
		context.Background(),
		bytes.NewReader(output.Bytes()),
		astits.DemuxerOptPacketSize(astits.MpegTsPacketSize),
	)
	gotFirst, err := dmx.NextPacket()
	if err != nil {
		t.Fatal(err)
	}
	gotSecond, err := dmx.NextPacket()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(gotFirst.Payload, first.Payload) {
		t.Fatalf("first PES payload = %x, want %x", gotFirst.Payload, first.Payload)
	}
	if !bytes.Equal(gotSecond.Payload, second.Payload) {
		t.Fatalf("second PES payload = %x, want %x", gotSecond.Payload, second.Payload)
	}
	if gotFirst.AdaptationField != nil && gotFirst.AdaptationField.HasPCR {
		t.Fatal("first PES received PCR from the following PUSI packet")
	}
	if gotSecond.AdaptationField == nil || !gotSecond.AdaptationField.HasPCR {
		t.Fatal("second PES lost its PCR")
	}
	if got := gotSecond.AdaptationField.PCR; got.Base != pcr.Base || got.Extension != pcr.Extension {
		t.Fatalf("second PES PCR = %+v, want %+v", got, pcr)
	}
}

func TestRemuxerPreservesIdentityPESPayloadsAndPacketCount(t *testing.T) {
	const videoPID = 0x100
	input := buildSyntheticTS(t, []tsStream{
		{pid: videoPID, streamType: astits.StreamTypeH264Video},
	}, []tsPES{
		{pid: videoPID, payload: append([]byte{0, 0, 0, 1, 0x65}, bytes.Repeat([]byte{0x55}, 251)...)},
	})

	var output bytes.Buffer
	remuxer := newRemuxer(astits.NewMuxer(context.Background(), &output), false, sampleaes.Config{})
	sink := newOutputAligner(videoPID)
	remuxer.streams = map[uint16]*mediaStream{
		videoPID: newMediaStream(
			videoPID,
			astits.StreamTypeH264Video,
			sink,
			&identityMediaTransformer{PESHandler: sink},
		),
	}
	if err := remuxer.pmt.Signal(videoPID)(func(*astits.PMTElementaryStream) {}); err != nil {
		t.Fatal(err)
	}
	dmx := astits.NewDemuxer(context.Background(), bytes.NewReader(input))
	for {
		packet, err := dmx.NextPacket()
		if err == astits.ErrNoMorePackets {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := remuxer.Consume(packet); err != nil {
			t.Fatal(err)
		}
	}
	if err := remuxer.Flush(); err != nil {
		t.Fatal(err)
	}

	if got, want := output.Len(), len(input); got != want {
		t.Fatalf("identity remux size = %d, want %d", got, want)
	}
	originalPES := demuxPESPayloads(t, bytes.NewReader(input))
	remuxedPES := demuxPESPayloads(t, bytes.NewReader(output.Bytes()))
	assertPESRoundTrip(t, originalPES, remuxedPES)
}

func TestRemuxerPreservesPESPayloadsWithNoopAVCTransformer(t *testing.T) {
	const videoPID = 0x100
	input := buildSyntheticTS(t, []tsStream{
		{pid: videoPID, streamType: astits.StreamTypeH264Video},
	}, []tsPES{
		{pid: videoPID, payload: append([]byte{0, 0, 0, 1, 0x65}, bytes.Repeat([]byte{0x55}, 251)...)},
	})

	var output bytes.Buffer
	remuxer := newRemuxer(astits.NewMuxer(context.Background(), &output), false, sampleaes.Config{})
	sink := newOutputAligner(videoPID)
	remuxer.streams = map[uint16]*mediaStream{
		videoPID: newMediaStream(
			videoPID,
			astits.StreamTypeH264Video,
			sink,
			newAVCTransformer(t, sink, noopBlockCryptor{}),
		),
	}
	if err := remuxer.pmt.Signal(videoPID)(func(*astits.PMTElementaryStream) {}); err != nil {
		t.Fatal(err)
	}
	dmx := astits.NewDemuxer(context.Background(), bytes.NewReader(input))
	for {
		packet, err := dmx.NextPacket()
		if err == astits.ErrNoMorePackets {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := remuxer.Consume(packet); err != nil {
			t.Fatal(err)
		}
	}
	if err := remuxer.Flush(); err != nil {
		t.Fatal(err)
	}

	if got, want := output.Len(), len(input); got != want {
		t.Fatalf("noop AVC remux size = %d, want %d", got, want)
	}
	originalPES := demuxPESPayloads(t, bytes.NewReader(input))
	remuxedPES := demuxPESPayloads(t, bytes.NewReader(output.Bytes()))
	assertPESRoundTrip(t, originalPES, remuxedPES)
}

func TestRemuxerInitializesMediaStreamsOnce(t *testing.T) {
	const videoPID = 0x100

	remuxer := newRemuxer(
		astits.NewMuxer(context.Background(), &bytes.Buffer{}),
		false,
		sampleaes.Config{Key: make([]byte, 16), IV: make([]byte, 16)},
	)
	initial := []*astits.PMTElementaryStream{
		{ElementaryPID: videoPID, StreamType: astits.StreamTypeH264Video},
	}
	if err := remuxer.updateMediaStreams(initial); err != nil {
		t.Fatal(err)
	}
	video := remuxer.streams[videoPID]
	if video == nil {
		t.Fatal("initial PMT did not create media stream")
	}

	if err := remuxer.updateMediaStreams(initial); err != nil {
		t.Fatal(err)
	}
	if remuxer.streams[videoPID] != video {
		t.Fatal("unchanged PMT replaced existing stream state")
	}

	updated := []*astits.PMTElementaryStream{
		{ElementaryPID: videoPID, StreamType: astits.StreamType(0xFF)},
	}
	if err := remuxer.updateMediaStreams(updated); err != nil {
		t.Fatal(err)
	}
	if remuxer.streams[videoPID] != video ||
		remuxer.streams[videoPID].streamType != astits.StreamTypeH264Video {
		t.Fatal("later PMT changed initialized media streams")
	}
}

func TestRemuxerPassesThroughSupportedPIDUntilFirstPESStart(t *testing.T) {
	const videoPID = 0x100

	var output bytes.Buffer
	remuxer := newRemuxer(
		astits.NewMuxer(context.Background(), &output),
		false,
		sampleaes.Config{Key: make([]byte, 16), IV: make([]byte, 16)},
	)
	if err := remuxer.updateMediaStreams([]*astits.PMTElementaryStream{{
		ElementaryPID: videoPID,
		StreamType:    astits.StreamTypeH264Video,
	}}); err != nil {
		t.Fatal(err)
	}

	payload := []byte{1, 2, 3}
	adaptation, err := astits.NewStuffingAdaptationField(
		mux.TSPacketPayloadCapacity - len(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	packet := &astits.Packet{
		Header: astits.PacketHeader{
			ContinuityCounter:  4,
			HasAdaptationField: true,
			HasPayload:         true,
			PID:                videoPID,
		},
		AdaptationField: adaptation,
		Payload:         payload,
	}
	if err := remuxer.Consume(packet); err != nil {
		t.Fatal(err)
	}

	if got, want := output.Len(), astits.MpegTsPacketSize; got != want {
		t.Fatalf("passthrough size = %d, want %d", got, want)
	}
	dmx := astits.NewDemuxer(
		context.Background(),
		bytes.NewReader(output.Bytes()),
		astits.DemuxerOptPacketSize(astits.MpegTsPacketSize),
	)
	got, err := dmx.NextPacket()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("passthrough payload = %v, want %v", got.Payload, payload)
	}
}
