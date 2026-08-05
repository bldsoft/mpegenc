package ts

import (
	"fmt"

	"mpegenc/internal/go-astits"

	"mpegenc/internal/utils"
	"mpegenc/ts/internal/packets"
	"mpegenc/ts/internal/pmtsignal"
	"mpegenc/ts/internal/transformer"
)

type pendingPMT struct {
	token   utils.CommitToken
	packet  *astits.Packet
	section *astits.PSISection
}

// pmtTransformer parses, modifies and emits PMT. Different codecs require
// different modifications of the PMT, some may just change specific header value
// and some may add whole new descriptors to the PMT.
// Modification may require additional info from the packets so it's transformers'
// responsibility to collect required info and modify PMT accordingly via signaling.
// PMT is buffered until all the transformers from supported codecs (which exist in
// the chunk) have signaled.
//
// BTW We can't buffer resulting PMT for their next occurences because theoretically
// they may change mid-stream... so its better to apply patches all over again every
// time.
type pmtTransformer struct {
	collector      *packets.PMTCollector
	inputEncrypted bool

	// Callback to invoke when PMT is ready to be emitted
	complete func(completedSlot) error

	patches map[uint16]pmtsignal.Patch

	// Since there may be multiple PMT packets in the chunk, we need to buffer them all
	// if we are still not ready to emit the PMT.
	pending     []pendingPMT
	initialized bool
}

func newPMTTransformer(
	inputEncrypted bool,
	complete func(completedSlot) error,
) *pmtTransformer {
	return &pmtTransformer{
		collector:      packets.NewPMTCollector(1),
		inputEncrypted: inputEncrypted,
		complete:       complete,
		patches:        make(map[uint16]pmtsignal.Patch),
	}
}

func (p *pmtTransformer) Consume(
	token utils.CommitToken,
	packet *astits.Packet,
) ([]*astits.PMTElementaryStream, error) {
	section, found, err := p.collectPMT(packet)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, p.complete(completedSlot{
			token:   token,
			packets: []*astits.Packet{astits.ClonePacket(packet)},
		})
	}

	streams := section.Syntax.Data.PMT.ElementaryStreams
	if !p.initialized {
		for _, stream := range streams {
			if transformer.SupportedMediaType(stream.StreamType, p.inputEncrypted) {
				if _, ok := p.patches[stream.ElementaryPID]; !ok {
					p.patches[stream.ElementaryPID] = nil
				}
			}
		}
		p.initialized = true
	}

	p.pending = append(p.pending, pendingPMT{
		token:   token,
		packet:  astits.ClonePacket(packet),
		section: section,
	})
	if err := p.completeReady(); err != nil {
		return nil, err
	}
	return streams, nil
}

func (p *pmtTransformer) Signal(pid uint16) pmtsignal.Signal {
	return func(patch pmtsignal.Patch) error {
		p.patches[pid] = patch
		return p.completeReady()
	}
}

func (p *pmtTransformer) collectPMT(packet *astits.Packet) (*astits.PSISection, bool, error) {
	if !packet.Header.HasPayload {
		return nil, false, nil
	}
	if !packet.Header.PayloadUnitStartIndicator {
		return nil, false, fmt.Errorf("split PMT is unsupported")
	}
	if len(packet.Payload) < 4 {
		return nil, false, fmt.Errorf("incomplete PMT payload")
	}
	if packet.Payload[0] != 0 {
		return nil, false, fmt.Errorf("PMT pointer field %d is unsupported", packet.Payload[0])
	}

	sectionLength := int(packet.Payload[2]&0x0F)<<8 | int(packet.Payload[3])
	sectionEnd := 4 + sectionLength
	if sectionEnd > len(packet.Payload) {
		return nil, false, fmt.Errorf("split PMT is unsupported")
	}
	for _, b := range packet.Payload[sectionEnd:] {
		if b != 0xFF {
			return nil, false, fmt.Errorf("multiple PMT sections in one packet are unsupported")
		}
	}

	return p.collector.Consume(
		packet.Header.PayloadUnitStartIndicator,
		packet.Payload,
	)
}

func (p *pmtTransformer) completeReady() error {
	for _, patch := range p.patches {
		if patch == nil {
			return nil
		}
	}

	for _, pending := range p.pending {
		for _, stream := range pending.section.Syntax.Data.PMT.ElementaryStreams {
			patch, ok := p.patches[stream.ElementaryPID]
			if !ok {
				continue
			}
			patch(stream)
		}

		output := pending.packet
		if len(p.patches) != 0 {
			pending.section.Syntax.Header.VersionNumber = (pending.section.Syntax.Header.VersionNumber + 1) & 0x1F
			var err error
			output, err = astits.PacketizePSISection(pending.packet, pending.section)
			if err != nil {
				return fmt.Errorf("packetize PMT: %w", err)
			}
		}
		if err := p.complete(completedSlot{
			token:   pending.token,
			packets: []*astits.Packet{output},
		}); err != nil {
			return err
		}
	}
	p.pending = nil
	return nil
}

func (p *pmtTransformer) Flush() error {
	if len(p.pending) != 0 {
		return fmt.Errorf(
			"PMT transformer: %d PMT packets remain unresolved: stream metadata not found before EOF",
			len(p.pending),
		)
	}
	return nil
}
