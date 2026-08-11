package mux

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

var testPESHeader = []byte{
	0x00, 0x00, 0x01, 0xE0,
	0x00, 0x00,
	0x80, 0x00, 0x00,
}

func TestTSPacketizerWritesPES(t *testing.T) {
	const pid = 0x100

	writer := NewTSPacketizer(pid)
	writer.SetContinuityCounter(15)
	payload := bytes.Repeat([]byte{0xAB}, 369)

	if err := writer.BeginPES(testPESHeader); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePESPayload(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.EndPES(); err != nil {
		t.Fatal(err)
	}

	packets := writer.TakePackets()
	if got, want := len(packets), 3; got != want {
		t.Fatalf("packet count = %d, want %d", got, want)
	}
	var reconstructed []byte
	for i, packet := range packets {
		reconstructed = append(reconstructed, packet.Payload...)
		wantCC := []uint8{15, 0, 1}[i]
		if packet.Header.ContinuityCounter != wantCC {
			t.Fatalf(
				"packet %d continuity counter = %d, want %d",
				i,
				packet.Header.ContinuityCounter,
				wantCC,
			)
		}
		if got, want := packet.Header.PayloadUnitStartIndicator, i == 0; got != want {
			t.Fatalf("packet %d PUSI = %t, want %t", i, got, want)
		}
	}
	wantPayload := append(append([]byte(nil), testPESHeader...), payload...)
	if !bytes.Equal(reconstructed, wantPayload) {
		t.Fatal("reconstructed payload differs from input")
	}
	if !packets[2].Header.HasAdaptationField {
		t.Fatal("partial packet has no adaptation stuffing")
	}
}

func TestTSPacketizerSetsAdaptationAfterEarlierPayload(t *testing.T) {
	const pid = 0x100

	writer := NewTSPacketizer(pid)
	beforePCR := bytes.Repeat([]byte{0x11}, 176-len(testPESHeader))
	afterPCR := bytes.Repeat([]byte{0x22}, 10)
	pcr := &astits.ClockReference{Base: 270_000}

	if err := writer.BeginPES(testPESHeader); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePESPayload(beforePCR); err != nil {
		t.Fatal(err)
	}
	if err := writer.SetNextPacketAdaptationField(&astits.PacketAdaptationField{
		HasPCR: true,
		PCR:    pcr,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePESPayload(afterPCR); err != nil {
		t.Fatal(err)
	}
	if err := writer.EndPES(); err != nil {
		t.Fatal(err)
	}

	packets := writer.TakePackets()
	if len(packets) != 2 {
		t.Fatalf("packet count = %d, want 2", len(packets))
	}
	if packets[0].AdaptationField != nil && packets[0].AdaptationField.HasPCR {
		t.Fatal("PCR attached to payload preceding its source packet")
	}
	if packets[1].AdaptationField == nil || !packets[1].AdaptationField.HasPCR {
		t.Fatal("PCR not attached to following payload")
	}
}

func TestTSPacketizerWritesAdaptationOnlyWithoutAdvancingCC(t *testing.T) {
	const pid = 0x100

	writer := NewTSPacketizer(pid)
	writer.SetContinuityCounter(8)
	if err := writer.WriteAdaptationOnly(
		&astits.PacketAdaptationField{
			HasPCR: true,
			PCR:    &astits.ClockReference{Base: 180_000},
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := writer.BeginPES(testPESHeader); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePESPayload([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EndPES(); err != nil {
		t.Fatal(err)
	}

	packets := writer.TakePackets()
	if got, want := len(packets), 2; got != want {
		t.Fatalf("packet count = %d, want %d", got, want)
	}
	if packets[0].Header.HasPayload {
		t.Fatal("adaptation-only packet has payload")
	}
	if packets[0].Header.ContinuityCounter != 7 {
		t.Fatalf("adaptation-only CC = %d, want 7", packets[0].Header.ContinuityCounter)
	}
	if packets[1].Header.ContinuityCounter != 8 {
		t.Fatalf("payload CC = %d, want 8", packets[1].Header.ContinuityCounter)
	}
}

func TestTSPacketizerFlushesBufferedPayloadBeforeAdaptationOnly(t *testing.T) {
	const pid = 0x100

	writer := NewTSPacketizer(pid)
	writer.SetContinuityCounter(8)
	if err := writer.BeginPES(testPESHeader); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePESPayload([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteAdaptationOnly(
		&astits.PacketAdaptationField{
			HasPCR: true,
			PCR:    &astits.ClockReference{Base: 180_000},
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePESPayload([]byte{4}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EndPES(); err != nil {
		t.Fatal(err)
	}

	packets := writer.TakePackets()
	if got, want := len(packets), 3; got != want {
		t.Fatalf("packet count = %d, want %d", got, want)
	}
	wantFirstPayload := append(append([]byte(nil), testPESHeader...), 1, 2, 3)
	if !bytes.Equal(packets[0].Payload, wantFirstPayload) {
		t.Fatalf("first payload = %v, want %v", packets[0].Payload, wantFirstPayload)
	}
	if packets[0].Header.ContinuityCounter != 8 {
		t.Fatalf("first payload CC = %d, want 8", packets[0].Header.ContinuityCounter)
	}
	if packets[1].Header.HasPayload {
		t.Fatal("middle adaptation-only packet has payload")
	}
	if packets[1].Header.ContinuityCounter != 8 {
		t.Fatalf("adaptation-only CC = %d, want 8", packets[1].Header.ContinuityCounter)
	}
	if !bytes.Equal(packets[2].Payload, []byte{4}) {
		t.Fatalf("last payload = %v, want [4]", packets[2].Payload)
	}
	if packets[2].Header.ContinuityCounter != 9 {
		t.Fatalf("last payload CC = %d, want 9", packets[2].Header.ContinuityCounter)
	}
}

func TestTSPacketizerPreservesAllAdaptationMetadata(t *testing.T) {
	const pid = 0x100

	source := &astits.PacketAdaptationField{
		AdaptationExtensionField: &astits.PacketAdaptationExtensionField{
			DTSNextAccessUnit:      &astits.ClockReference{Base: 45_000},
			HasLegalTimeWindow:     true,
			HasPiecewiseRate:       true,
			HasSeamlessSplice:      true,
			LegalTimeWindowIsValid: true,
			LegalTimeWindowOffset:  42,
			PiecewiseRate:          100,
			SpliceType:             2,
		},
		DiscontinuityIndicator:            true,
		ElementaryStreamPriorityIndicator: true,
		HasAdaptationExtensionField:       true,
		HasOPCR:                           true,
		HasPCR:                            true,
		HasSplicingCountdown:              true,
		HasTransportPrivateData:           true,
		OPCR:                              &astits.ClockReference{Base: 90_000},
		PCR:                               &astits.ClockReference{Base: 180_000},
		RandomAccessIndicator:             true,
		SpliceCountdown:                   255,
		TransportPrivateData:              []byte{1, 2, 3},
		TransportPrivateDataLength:        3,
	}
	writer := NewTSPacketizer(pid)
	if err := writer.SetNextPacketAdaptationField(source); err != nil {
		t.Fatal(err)
	}
	if err := writer.BeginPES(testPESHeader); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePESPayload([]byte{0xAB}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EndPES(); err != nil {
		t.Fatal(err)
	}

	packets := writer.TakePackets()
	got := astits.CloneAdaptationFieldWithoutStuffing(
		packets[0].AdaptationField,
	)
	want := astits.CloneAdaptationFieldWithoutStuffing(source)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adaptation metadata = %+v, want %+v", got, want)
	}
}

func TestTSPacketizerValidatesPESLifecycle(t *testing.T) {
	packetizer := NewTSPacketizer(0x100)

	if err := packetizer.WritePESPayload([]byte{1}); err == nil {
		t.Fatal("write outside PES succeeded")
	}
	if err := packetizer.EndPES(); err == nil {
		t.Fatal("end outside PES succeeded")
	}
	if err := packetizer.BeginPES(testPESHeader); err != nil {
		t.Fatal(err)
	}
	if err := packetizer.Flush(); err == nil {
		t.Fatal("flush with open PES succeeded")
	}
	if err := packetizer.BeginPES(testPESHeader); err == nil {
		t.Fatal("nested PES begin succeeded")
	}
	if err := packetizer.EndPES(); err != nil {
		t.Fatal(err)
	}
}

func TestTSPacketizerForwardsHeaderAndPayloadAsOnePES(t *testing.T) {
	packetizer := NewTSPacketizer(0x100)
	payload := bytes.Repeat([]byte{0xAB}, 360)

	if err := packetizer.BeginPES(testPESHeader); err != nil {
		t.Fatal(err)
	}
	if err := packetizer.WritePESPayload(payload[:100]); err != nil {
		t.Fatal(err)
	}
	if err := packetizer.WritePESPayload(payload[100:]); err != nil {
		t.Fatal(err)
	}
	if err := packetizer.EndPES(); err != nil {
		t.Fatal(err)
	}

	packets := packetizer.TakePackets()
	var pesBytes []byte
	for i, packet := range packets {
		pesBytes = append(pesBytes, packet.Payload...)
		if got, want := packet.Header.PayloadUnitStartIndicator, i == 0; got != want {
			t.Fatalf("packet %d PUSI = %t, want %t", i, got, want)
		}
	}
	want := append(append([]byte(nil), testPESHeader...), payload...)
	if !bytes.Equal(pesBytes, want) {
		t.Fatal("reconstructed PES differs from input")
	}
	if packets := packetizer.TakePackets(); len(packets) != 0 {
		t.Fatalf("second TakePackets returned %d packets", len(packets))
	}
}

func TestTSPacketizerStartsEachPESWithPUSI(t *testing.T) {
	packetizer := NewTSPacketizer(0x100)

	for i := 0; i < 2; i++ {
		if err := packetizer.BeginPES(testPESHeader); err != nil {
			t.Fatal(err)
		}
		if err := packetizer.WritePESPayload([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		if err := packetizer.EndPES(); err != nil {
			t.Fatal(err)
		}
	}

	packets := packetizer.TakePackets()
	if len(packets) != 2 {
		t.Fatalf("packet count = %d, want 2", len(packets))
	}
	for i, packet := range packets {
		if !packet.Header.PayloadUnitStartIndicator {
			t.Fatalf("PES packet %d has no PUSI", i)
		}
	}
}
