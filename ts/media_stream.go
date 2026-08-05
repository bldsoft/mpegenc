package ts

import (
	"fmt"

	"mpegenc/internal/go-astits"

	"mpegenc/internal/utils"
	"mpegenc/ts/codecs"
	"mpegenc/ts/packets"
)

type mediaStream struct {
	pid         uint16
	streamType  astits.StreamType
	sink        *outputAligner
	pes         packets.PESCollector
	transformer codecs.MediaTransformer
}

func newMediaStream(
	pid uint16,
	streamType astits.StreamType,
	sink *outputAligner,
	transformer codecs.MediaTransformer,
) *mediaStream {
	return &mediaStream{
		pid:         pid,
		streamType:  streamType,
		sink:        sink,
		transformer: transformer,
	}
}

func (s *mediaStream) Active() bool {
	return s.pes.Active()
}

// Consume feeds one input packet through the pipeline under the output slot
// reserved for it.
func (s *mediaStream) Consume(
	token utils.CommitToken,
	packet *astits.Packet,
) ([]completedSlot, error) {
	if packet == nil {
		return nil, fmt.Errorf("media stream PID 0x%04X: nil packet", s.pid)
	}
	if packet.Header.PID != s.pid {
		return nil, fmt.Errorf(
			"media stream PID 0x%04X: received packet for PID 0x%04X",
			s.pid,
			packet.Header.PID,
		)
	}
	if err := s.sink.registerInputPacket(token, packet); err != nil {
		return nil, err
	}

	// Pipeline will produce slots on its own via the transformer
	if err := s.pes.Consume(
		packet.Header.PayloadUnitStartIndicator,
		packet.Payload,
		s.transformer,
	); err != nil {
		return nil, err
	}
	return s.sink.align(), nil
}

func (s *mediaStream) Flush() ([]completedSlot, error) {
	if err := s.pes.Flush(s.transformer); err != nil {
		return nil, err
	}
	if err := s.transformer.Flush(); err != nil {
		return nil, err
	}
	return s.sink.flush()
}
