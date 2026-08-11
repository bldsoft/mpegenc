package ts

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"

	"github.com/bldsoft/mpegenc/sampleaes"
)

func TestEncryptRewritesSampleAESPMT(t *testing.T) {
	const (
		videoPID = 0x100
		audioPID = 0x101
	)
	input := buildSyntheticTS(t, []tsStream{
		{pid: videoPID, streamType: astits.StreamTypeH264Video},
		{pid: audioPID, streamType: astits.StreamTypeADTS},
	}, []tsPES{
		{pid: videoPID, payload: annexBSliceNAL(t, 128)},
		{pid: audioPID, payload: adtsLikePayload(64)},
	})
	key, iv := testKeyIV()
	var output bytes.Buffer
	if err := Encrypt(t.Context(), bytes.NewReader(input), &output, sampleaes.Config{Key: key, IV: iv}); err != nil {
		t.Fatal(err)
	}
	for _, stream := range findPMT(t, output.Bytes()).ElementaryStreams {
		switch stream.ElementaryPID {
		case videoPID:
			if stream.StreamType != 0xDB {
				t.Fatalf("video stream type = 0x%02X", stream.StreamType)
			}
			if len(stream.ElementaryStreamDescriptors) != 1 ||
				stream.ElementaryStreamDescriptors[0].PrivateDataIndicator == nil ||
				stream.ElementaryStreamDescriptors[0].PrivateDataIndicator.Indicator != 0x7A617663 {
				t.Fatal("video stream has no zavc descriptor")
			}
		case audioPID:
			if stream.StreamType != 0xCF {
				t.Fatalf("audio stream type = 0x%02X", stream.StreamType)
			}
			if len(stream.ElementaryStreamDescriptors) != 2 ||
				stream.ElementaryStreamDescriptors[0].PrivateDataIndicator == nil ||
				stream.ElementaryStreamDescriptors[0].PrivateDataIndicator.Indicator != 0x61616364 {
				t.Fatal("audio stream has no aacd descriptor")
			}
			registration := stream.ElementaryStreamDescriptors[1].Registration
			if registration == nil || registration.FormatIdentifier != 0x61706164 ||
				!bytes.Equal(registration.AdditionalIdentificationInfo, []byte{
					'z', 'a', 'a', 'c', 0, 0, 1, 2, 0x12, 0x10,
				}) {
				t.Fatal("audio stream has invalid apad descriptor")
			}
		}
	}
}

func TestPMTProcessorReleasesRepeatedPMTsAfterAACConfig(t *testing.T) {
	const audioPID = 0x101
	input := buildSyntheticTS(t, []tsStream{
		{pid: audioPID, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: audioPID, payload: adtsLikePayload(64)}})
	packet := findPMTPacket(t, input)
	completed := make([]completedSlot, 0, 3)
	processor := newPMTTransformer(false, func(slot completedSlot) error {
		completed = append(completed, slot)
		return nil
	})

	_, err := processor.Consume(0, packet)
	if err != nil {
		t.Fatal(err)
	}
	_, err = processor.Consume(1, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(completed) != 0 || len(processor.pending) != 2 {
		t.Fatal("PMT packets were not held")
	}

	if err := processor.Signal(audioPID)(func(*astits.PMTElementaryStream) {}); err != nil {
		t.Fatal(err)
	}
	if len(completed) != 2 || completed[0].token != 0 || completed[1].token != 1 {
		t.Fatalf("completed = %+v", completed)
	}
	if len(processor.pending) != 0 {
		t.Fatalf("pending PMTs = %d", len(processor.pending))
	}

	_, err = processor.Consume(2, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(completed) != 3 || completed[2].token != 2 {
		t.Fatalf("completed = %+v", completed)
	}
}

func TestPMTProcessorRejectsSplitPMT(t *testing.T) {
	const audioPID = 0x101
	input := buildSyntheticTS(t, []tsStream{
		{pid: audioPID, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: audioPID, payload: adtsLikePayload(64)}})
	packet := astits.ClonePacket(findPMTPacket(t, input))
	packet.Payload = packet.Payload[:8]

	processor := newPMTTransformer(false, func(completedSlot) error { return nil })
	_, err := processor.Consume(0, packet)
	if err == nil || !strings.Contains(err.Error(), "split PMT is unsupported") {
		t.Fatalf("error = %v", err)
	}
}

func TestEncryptFailsWhenAACConfigIsMissingAtEOF(t *testing.T) {
	const audioPID = 0x101
	input := buildSyntheticTS(t, []tsStream{
		{pid: audioPID, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: audioPID}})
	key, iv := testKeyIV()

	err := Encrypt(
		t.Context(),
		bytes.NewReader(input),
		&bytes.Buffer{},
		sampleaes.Config{Key: key, IV: iv},
	)
	if err == nil || !strings.Contains(err.Error(), "stream metadata not found before EOF") {
		t.Fatalf("error = %v", err)
	}
}

func findPMT(t *testing.T, data []byte) *astits.PMTData {
	t.Helper()
	demuxer := astits.NewDemuxer(context.Background(), bytes.NewReader(data))
	for {
		item, err := demuxer.NextData()
		if err == astits.ErrNoMorePackets {
			t.Fatal("PMT not found")
		}
		if err != nil {
			t.Fatal(err)
		}
		if item.PMT != nil {
			return item.PMT
		}
	}
}

func findPMTPacket(t *testing.T, data []byte) *astits.Packet {
	t.Helper()
	demuxer := astits.NewDemuxer(context.Background(), bytes.NewReader(data))
	for {
		packet, err := demuxer.NextPacket()
		if err == astits.ErrNoMorePackets {
			t.Fatal("PMT packet not found")
		}
		if err != nil {
			t.Fatal(err)
		}
		if packet.Header.PayloadUnitStartIndicator &&
			len(packet.Payload) > 1 &&
			packet.Payload[0] == 0 &&
			packet.Payload[1] == byte(astits.PSITableIDPMT) {
			return packet
		}
	}
}
