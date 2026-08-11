package packets

import (
	"bytes"
	"context"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

func TestPMTCollectorFindsProgramStreams(t *testing.T) {
	const (
		programNumber = 1
		pmtPID        = 0x1000
		videoPID      = 0x100
		audioPID      = 0x101
	)
	stream := buildSyntheticTS(t, []tsStream{
		{pid: videoPID, streamType: astits.StreamTypeH264Video},
		{pid: audioPID, streamType: astits.StreamTypeADTS},
	}, []tsPES{
		{pid: videoPID, payload: annexBSliceNAL(t, 64)},
		{pid: audioPID, payload: adtsLikePayload(64)},
	})

	dmx := astits.NewDemuxer(context.Background(), bytes.NewReader(stream))
	collector := NewPMTCollector(programNumber)
	for {
		pkt, err := dmx.NextPacket()
		if err == astits.ErrNoMorePackets {
			t.Fatal("PMT was not found")
		}
		if err != nil {
			t.Fatalf("NextPacket: %v", err)
		}
		if pkt.Header.PID != pmtPID {
			continue
		}

		section, found, err := collector.Consume(pkt.Header.PayloadUnitStartIndicator, pkt.Payload)
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if !found {
			continue
		}
		pmt := section.Syntax.Data.PMT
		if pmt.PCRPID != videoPID {
			t.Fatalf("PCR PID = 0x%04X, want 0x%04X", pmt.PCRPID, videoPID)
		}
		if len(pmt.ElementaryStreams) != 2 {
			t.Fatalf("stream count = %d, want 2", len(pmt.ElementaryStreams))
		}
		if pmt.ElementaryStreams[0].ElementaryPID != videoPID ||
			pmt.ElementaryStreams[0].StreamType != astits.StreamTypeH264Video {
			t.Fatal("unexpected video PMT entry")
		}
		if pmt.ElementaryStreams[1].ElementaryPID != audioPID ||
			pmt.ElementaryStreams[1].StreamType != astits.StreamTypeADTS {
			t.Fatal("unexpected audio PMT entry")
		}
		return
	}
}

func TestPMTCollectorIgnoresFutureTable(t *testing.T) {
	const pmtPID = 0x1000
	stream := buildSyntheticTS(t, []tsStream{
		{pid: 0x101, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: 0x101, payload: adtsLikePayload(64)}})

	dmx := astits.NewDemuxer(context.Background(), bytes.NewReader(stream))
	for {
		packet, err := dmx.NextPacket()
		if err != nil {
			t.Fatal(err)
		}
		if packet.Header.PID != pmtPID {
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

		_, found, err := NewPMTCollector(1).Consume(true, append([]byte{0}, future...))
		if err != nil {
			t.Fatal(err)
		}
		if found {
			t.Fatal("PMT collector applied a future table")
		}
		return
	}
}
