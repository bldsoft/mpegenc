package ts

import (
	"fmt"

	"github.com/bldsoft/mpegenc/internal/go-astits"

	"github.com/bldsoft/mpegenc/internal/utils"
	"github.com/bldsoft/mpegenc/ts/internal/mux"
)

type packetMetadata struct {
	cc         uint8
	hasPayload bool
	adaptation *astits.PacketAdaptationField
}

// completedSlot is one input position whose replacement packets are ready.
type completedSlot struct {
	token utils.CommitToken
	// packets is the complete replacement for this input position. It may contain
	// zero packets, one packet, or several packets after repacketization
	packets []*astits.Packet
}

// pendingPESMetadata is the FIFO entry for one source PES.
// TODO Add some limits?
type pendingPESMetadata struct {
	startAdaptation *astits.PacketAdaptationField
	events          []packetMetadata
}

type outputAligner struct {
	packetizer *mux.TSPacketizer

	// pendingPES delays source metadata until the matching regenerated PES starts.
	// e.g. we receive PES B: PUSI=true with PCR
	// meanwhile codec is still processing PES A, so TSPacketizer still produces output PES A
	//
	// if we pass PCR instantly, it will be attached to PES A so we need to buffer it until PESHeader(B)
	pendingPES []pendingPESMetadata

	// ccInitialized prevents later source packets from resetting the regenerated cc
	ccInitialized bool

	// tokens are source slots consumed for this PID but not fully matched to regenerated
	// TS packet yet
	tokens []utils.CommitToken
	// pending keeps the last matched slot uncommitted so delayed packets can still be appended
	// after its token was consumed
	//
	// there was a problem with Flush() where align() have already consumed the token but
	// h264 transformer produced more packets on the flush and we couldnt place them anywhere anymore
	pending *completedSlot
}

func newOutputAligner(pid uint16) *outputAligner {
	return &outputAligner{packetizer: mux.NewTSPacketizer(pid)}
}

// registerInputPacket saves this input packet's metadata and its place in the output order.
func (a *outputAligner) registerInputPacket(token utils.CommitToken, packet *astits.Packet) error {
	meta := a.clonePacketMetadata(packet)
	if !a.ccInitialized {
		cc := meta.cc
		if !meta.hasPayload {
			cc = (cc + 1) & 0x0F
		}
		a.packetizer.SetContinuityCounter(cc)
		a.ccInitialized = true
	}
	var err error

	switch {
	// New PES starts
	case meta.hasPayload && packet.Header.PayloadUnitStartIndicator:
		// TSPacketizer may still contain the previous PES tail. Applying the new
		// PUSI packet's PCR now could attach it to that tail, so delay it until
		// PESHeader confirms that the regenerated new PES has actually begun
		a.pendingPES = append(a.pendingPES, pendingPESMetadata{
			startAdaptation: meta.adaptation,
		})

	// We've received input PUSI packet before and now we received another packet with meaningful adaptation
	// data. But we cant apply it before PESHeader()
	case len(a.pendingPES) > 0 && meta.adaptation != nil:
		// Codec buffering can let more source TS packets arrive before the delayed
		// PES header is emitted. Preserve their metadata in arrival order beside
		// the same pending PES
		pending := &a.pendingPES[len(a.pendingPES)-1]
		pending.events = append(pending.events, meta)
	case !meta.hasPayload:
		err = a.packetizer.WriteAdaptationOnly(meta.adaptation)
	default:
		// Ordinary payload metadata belongs on the next regenerated payload packet
		err = a.packetizer.SetNextPacketAdaptationField(meta.adaptation)
	}
	if err != nil {
		return err
	}
	a.tokens = append(a.tokens, token)
	return nil
}

func (a *outputAligner) PESHeader(header []byte) error {
	// Pop the oldest group because source PES order must remain stable
	pending := a.pendingPES[0]
	a.pendingPES[0] = pendingPESMetadata{}
	a.pendingPES = a.pendingPES[1:]

	// Schedule PUSI packet metadata before writing header bytes so it lands on the
	// first output TS packet of this PES
	if err := a.packetizer.SetNextPacketAdaptationField(pending.startAdaptation); err != nil {
		// This is some strange rare case, possibly broken input.
		// Nothing was transferred, so restore the complete group for a
		// caller retry or orderly error handling
		a.pendingPES = append(
			[]pendingPESMetadata{pending},
			a.pendingPES...,
		)
		return err
	}
	pending.startAdaptation = nil
	if err := a.packetizer.BeginPES(header); err != nil {
		return err
	}
	// Replay subsequent source metadata in exact arrival order
	for i := range pending.events {
		event := pending.events[i]
		pending.events[i].adaptation = nil
		var err error
		if !event.hasPayload {
			err = a.packetizer.WriteAdaptationOnly(event.adaptation)
		} else {
			err = a.packetizer.SetNextPacketAdaptationField(event.adaptation)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *outputAligner) PESPayload(payload []byte) error {
	return a.packetizer.WritePESPayload(payload)
}

func (a *outputAligner) PESEnd() error {
	return a.packetizer.EndPES()
}

// align assigns the packets emitted so far to the oldest pending tokens, one
// packet per token, spilling any surplus onto the last matched token. Tokens
// left without a packet stay pending for a later call.
func (a *outputAligner) align() []completedSlot {
	packets := a.packetizer.TakePackets()
	completed := make([]completedSlot, 0, min(len(packets), len(a.tokens)))
	if a.pending != nil {
		if len(a.tokens) == 0 {
			a.pending.packets = append(a.pending.packets, packets...)
			return nil
		}
		completed = append(completed, *a.pending)
		a.pending = nil
	}
	if len(packets) == 0 {
		// No output is normal: PES parsing or codec transformation may need more
		// source packets before it can finish enough data to emit a TS packet
		return completed
	}
	// We can match only pairs that exist on both sides. Extra tokens wait for
	// future output; extra packets cannot receive newly invented global slots
	count := min(len(packets), len(a.tokens))
	for i := range count {
		slotPackets := []*astits.Packet{packets[i]}
		if len(packets) > count && i == count-1 {
			// Attach every surplus packet to the final matched token so their local
			// order is preserved without shifting any later global slot
			slotPackets = append(slotPackets, packets[count:]...)
		}
		completed = append(completed, completedSlot{
			token:   a.tokens[i],
			packets: slotPackets,
		})
	}
	a.tokens = a.tokens[count:]
	if count > 0 {
		pending := completed[len(completed)-1]
		completed = completed[:len(completed)-1]
		a.pending = &pending
	}
	return completed
}

func (a *outputAligner) flush() ([]completedSlot, error) {
	if err := a.packetizer.Flush(); err != nil {
		return nil, err
	}
	completed := a.align()
	if a.pending != nil {
		completed = append(completed, *a.pending)
		a.pending = nil
	}
	for _, token := range a.tokens {
		completed = append(completed, completedSlot{token: token})
	}
	a.tokens = a.tokens[:0]
	return completed, nil
}

// outputAssembler owns global output ordering. Every input packet reserves one slot
type outputAssembler struct {
	// queue contains one slot per input TS packet across every PID
	queue *utils.CommitQueue[[]*astits.Packet]
	// writer is the final packet sink
	writer *astits.Muxer
}

func newOutputAssembler(writer *astits.Muxer) *outputAssembler {
	return &outputAssembler{
		queue:  &utils.CommitQueue[[]*astits.Packet]{},
		writer: writer,
	}
}

// Reserve records one input TS packet's position.
func (a *outputAssembler) Reserve() utils.CommitToken {
	return a.queue.Reserve()
}

// Commit completes a slot with its final replacement packets.
func (a *outputAssembler) Commit(slot completedSlot) error {
	if err := a.queue.Commit(slot.token, slot.packets); err != nil {
		return fmt.Errorf("assembler: commit token %d: %w", slot.token, err)
	}
	// Committing any token can complete the ready prefix, so attempt a drain
	return a.Drain()
}

// CommitOriginal completes a slot with a detached copy of its source packet. Clones the packet.
func (a *outputAssembler) CommitOriginal(token utils.CommitToken, packet *astits.Packet) error {
	return a.Commit(completedSlot{
		token:   token,
		packets: []*astits.Packet{astits.ClonePacket(packet)},
	})
}

// Drain writes the longest ready prefix of the global queue.
func (a *outputAssembler) Drain() error {
	if a.writer == nil {
		return fmt.Errorf("assembler: nil TS writer")
	}
	return a.queue.Drain(func(packets []*astits.Packet) error {
		for _, packet := range packets {
			if _, err := a.writer.WritePacket(packet); err != nil {
				return fmt.Errorf(
					"assembler: write output PID 0x%04X: %w",
					packet.Header.PID,
					err,
				)
			}
		}
		return nil
	})
}

func (a *outputAssembler) Flush() error {
	if err := a.Drain(); err != nil {
		return err
	}
	if n := a.queue.Len(); n != 0 {
		return fmt.Errorf("assembler: %d output slots remain unresolved", n)
	}
	return nil
}

func (a *outputAssembler) Len() int {
	return a.queue.Len()
}

func (a *outputAligner) clonePacketMetadata(packet *astits.Packet) packetMetadata {
	meta := packetMetadata{
		cc:         packet.Header.ContinuityCounter & 0x0F,
		hasPayload: packet.Header.HasPayload,
	}

	// We will handle stuffing later, drop the original one
	if astits.HasAdaptationFieldData(packet.AdaptationField) {
		meta.adaptation = astits.CloneAdaptationFieldWithoutStuffing(packet.AdaptationField)
	}
	return meta
}
