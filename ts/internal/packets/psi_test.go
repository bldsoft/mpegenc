package packets

import (
	"bytes"
	"context"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

func TestPSISectionCollectorHandlesSplitAndAdjacentSections(t *testing.T) {
	stream := buildSyntheticTS(t, []tsStream{
		{pid: 0x101, streamType: astits.StreamTypeADTS},
	}, []tsPES{{pid: 0x101, payload: adtsLikePayload(64)}})

	dmx := astits.NewDemuxer(context.Background(), bytes.NewReader(stream))
	var pat []byte
	for {
		pkt, err := dmx.NextPacket()
		if err != nil {
			t.Fatalf("NextPacket: %v", err)
		}
		if pkt.Header.PID != astits.PIDPAT {
			continue
		}

		sectionStart := 1 + int(pkt.Payload[0])
		sectionLength := int(pkt.Payload[sectionStart+1]&0x0F)<<8 | int(pkt.Payload[sectionStart+2])
		pat = append([]byte(nil), pkt.Payload[sectionStart:sectionStart+3+sectionLength]...)
		break
	}

	collector := &psiSectionCollector{}
	sections, err := collector.Consume(true, append([]byte{0}, pat[:5]...))
	if err != nil {
		t.Fatalf("Consume first fragment: %v", err)
	}
	if len(sections) != 0 {
		t.Fatalf("sections after first fragment = %d, want 0", len(sections))
	}

	sections, err = collector.Consume(false, append(pat[5:], pat...))
	if err != nil {
		t.Fatalf("Consume remaining data: %v", err)
	}
	if len(sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(sections))
	}
	for i, got := range sections {
		if !bytes.Equal(got, pat) {
			t.Fatalf("section %d differs from the original PAT", i)
		}
	}
}
