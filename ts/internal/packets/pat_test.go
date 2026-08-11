package packets

import (
	"bytes"
	"context"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

func TestPATCollectorFindsProgramPMTPID(t *testing.T) {
	const (
		programNumber  = 1
		expectedPMTPID = 0x1000
		audioPID       = 0x101
	)
	stream := buildSyntheticTS(t, []tsStream{
		{pid: audioPID, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: audioPID, payload: adtsLikePayload(64)}})

	dmx := astits.NewDemuxer(context.Background(), bytes.NewReader(stream))
	collector := NewPATCollector(programNumber)

	for {
		pkt, err := dmx.NextPacket()
		if err == astits.ErrNoMorePackets {
			t.Fatal("PAT did not contain the requested program")
		}
		if err != nil {
			t.Fatalf("NextPacket: %v", err)
		}
		if pkt.Header.PID != 0 {
			continue
		}

		foundPMTPID, found, err := collector.Consume(pkt.Header.PayloadUnitStartIndicator, pkt.Payload)
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if found {
			if foundPMTPID != expectedPMTPID {
				t.Fatalf("PMT PID = 0x%04X, want 0x%04X", foundPMTPID, expectedPMTPID)
			}
			return
		}
	}
}

func TestPATCollectorRejectsInvalidCRC(t *testing.T) {
	stream := buildSyntheticTS(t, []tsStream{
		{pid: 0x101, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: 0x101, payload: adtsLikePayload(64)}})

	dmx := astits.NewDemuxer(context.Background(), bytes.NewReader(stream))
	collector := NewPATCollector(1)

	for {
		pkt, err := dmx.NextPacket()
		if err != nil {
			t.Fatalf("NextPacket: %v", err)
		}
		if pkt.Header.PID != 0 {
			continue
		}

		payload := append([]byte(nil), pkt.Payload...)
		sectionStart := 1 + int(payload[0])
		sectionLength := int(payload[sectionStart+1]&0x0F)<<8 | int(payload[sectionStart+2])
		payload[sectionStart+3+sectionLength-1] ^= 0x01 // corrupt the last CRC byte
		_, _, err = collector.Consume(pkt.Header.PayloadUnitStartIndicator, payload)
		if err == nil {
			t.Fatal("Consume succeeded with an invalid PAT CRC")
		}
		return
	}
}

func TestPATCollectorIgnoresFutureTable(t *testing.T) {
	stream := buildSyntheticTS(t, []tsStream{
		{pid: 0x101, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: 0x101, payload: adtsLikePayload(64)}})

	dmx := astits.NewDemuxer(context.Background(), bytes.NewReader(stream))
	for {
		packet, err := dmx.NextPacket()
		if err != nil {
			t.Fatal(err)
		}
		if packet.Header.PID != astits.PIDPAT {
			continue
		}

		sectionStart := 1 + int(packet.Payload[0])
		sectionLength := int(packet.Payload[sectionStart+1]&0x0F)<<8 |
			int(packet.Payload[sectionStart+2])
		section, err := astits.ParsePSISection(
			packet.Payload[sectionStart : sectionStart+3+sectionLength],
		)
		if err != nil {
			t.Fatal(err)
		}
		section.Syntax.Header.CurrentNextIndicator = false
		future, err := astits.MarshalPSISection(section)
		if err != nil {
			t.Fatal(err)
		}

		_, found, err := NewPATCollector(1).Consume(true, append([]byte{0}, future...))
		if err != nil {
			t.Fatal(err)
		}
		if found {
			t.Fatal("PAT collector applied a future table")
		}
		return
	}
}
