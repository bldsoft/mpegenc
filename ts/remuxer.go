package ts

import (
	"fmt"

	"github.com/bldsoft/mpegenc/internal/go-astits"

	"github.com/bldsoft/mpegenc/sampleaes"
	"github.com/bldsoft/mpegenc/ts/internal/packets"
	"github.com/bldsoft/mpegenc/ts/internal/transformer"
)

// remuxer is the central packet router.
// Cant expose it due to usage of the internal astits clone.
// TODO Find a workaround?
type remuxer struct {
	pat *packets.PATCollector
	pmt *pmtTransformer

	// TODO Use uint32 for runtime fast path?
	streams map[uint16]*mediaStream
	output  *outputAssembler

	pmtPID         uint16
	inputEncrypted bool

	cfg sampleaes.Config
}

// Ignores decrypt yet
func newRemuxer(writer *astits.Muxer, inputEncrypted bool, cfg sampleaes.Config) *remuxer {
	remuxer := &remuxer{
		inputEncrypted: inputEncrypted,
		pat:            packets.NewPATCollector(1),
		output:         newOutputAssembler(writer),
		cfg:            cfg,
	}
	remuxer.pmt = newPMTTransformer(inputEncrypted, remuxer.output.Commit)
	return remuxer
}

func (r *remuxer) Consume(packet *astits.Packet) error {
	if packet == nil {
		return fmt.Errorf("remuxer: nil packet")
	}

	token := r.output.Reserve()
	pid := packet.Header.PID
	switch pid {
	case astits.PIDPAT:
		pmtPID, found, err := r.pat.Consume(
			packet.Header.PayloadUnitStartIndicator,
			packet.Payload,
		)
		if err != nil {
			return fmt.Errorf("remuxer: collect PAT: %w", err)
		}
		if found {
			r.pmtPID = pmtPID
		}
		// No need to modify this
		return r.output.CommitOriginal(token, packet)
	case r.pmtPID:
		streams, err := r.pmt.Consume(token, packet)
		if err != nil {
			return fmt.Errorf("remuxer: process PMT: %w", err)
		}
		if streams != nil {
			if err := r.updateMediaStreams(streams); err != nil {
				return err
			}
		}
		return nil
	default:
		if stream, ok := r.streams[pid]; ok {
			// We didn't see pusi yet? Passthrough
			if !stream.Active() && packet.Header.HasPayload && !packet.Header.PayloadUnitStartIndicator {
				return r.output.CommitOriginal(token, packet)
			}
			completed, err := stream.Consume(token, packet)
			if err != nil {
				return fmt.Errorf("remuxer: media PID 0x%04X: %w", pid, err)
			}
			return r.commit(completed)
		}
		// Pass unrecognized streams as is
		return r.output.CommitOriginal(token, packet)
	}
}

func (r *remuxer) Flush() error {
	for pid, stream := range r.streams {
		completed, err := stream.Flush()
		if err != nil {
			return fmt.Errorf("remuxer: flush media PID 0x%04X: %w", pid, err)
		}
		if err := r.commit(completed); err != nil {
			return fmt.Errorf("remuxer: flush media PID 0x%04X: %w", pid, err)
		}
	}
	if err := r.pmt.Flush(); err != nil {
		return fmt.Errorf("remuxer: flush PMT: %w", err)
	}
	return r.output.Flush()
}

func (r *remuxer) commit(completed []completedSlot) error {
	for _, slot := range completed {
		if err := r.output.Commit(slot); err != nil {
			return err
		}
	}
	return nil
}

// Fills mediastreams if not already filled. Ignore new ones otherwise
// TODO better update them if something has changed.
func (r *remuxer) updateMediaStreams(streams []*astits.PMTElementaryStream) error {
	if r.streams != nil {
		return nil
	}

	pidToStreamType := make(map[uint16]astits.StreamType, len(streams))
	for _, stream := range streams {
		if !transformer.SupportedMediaType(stream.StreamType, r.inputEncrypted) {
			continue
		}
		if _, duplicate := pidToStreamType[stream.ElementaryPID]; duplicate {
			continue
		}
		pidToStreamType[stream.ElementaryPID] = stream.StreamType
	}

	r.streams = make(map[uint16]*mediaStream, len(pidToStreamType))
	for pid, streamType := range pidToStreamType {
		sink := newOutputAligner(pid)
		mediaTransformer, err := transformer.NewTransformer(
			streamType,
			sink,
			r.cfg,
			r.pmt.Signal(pid),
		)
		if err != nil {
			return fmt.Errorf("remuxer: create media PID 0x%04X: %w", pid, err)
		}
		r.streams[pid] = newMediaStream(pid, streamType, sink, mediaTransformer)
	}
	return nil
}
