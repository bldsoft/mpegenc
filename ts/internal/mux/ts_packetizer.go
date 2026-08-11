package mux

import (
	"fmt"

	"github.com/bldsoft/mpegenc/internal/go-astits"
)

const TSPacketPayloadCapacity = astits.MpegTsPacketSize - 4

// pendingTSPacket holds the not-yet-emitted payload and metadata for one output TS packet.
type pendingTSPacket struct {
	payload    [TSPacketPayloadCapacity]byte
	payloadLen int
	pusi       bool
	adaptation *astits.PacketAdaptationField
}

func payloadCapacity(adaptation *astits.PacketAdaptationField) (int, error) {
	if adaptation == nil {
		// Without an adaptation field, all 184 body bytes can carry PES data
		return TSPacketPayloadCapacity, nil
	}
	// This size includes the adaptation_field_length byte. Source stuffing was
	// removed before the field was transferred, so only meaningful metadata is reserved
	size := astits.AdaptationFieldSizeWithoutStuffing(adaptation)
	if size > TSPacketPayloadCapacity {
		return 0, fmt.Errorf("adaptation field requires %d bytes, maximum is %d", size, TSPacketPayloadCapacity)
	}
	return TSPacketPayloadCapacity - size, nil
}

func (p *pendingTSPacket) reset() {
	*p = pendingTSPacket{}
}

// TSPacketizer packetizes one PID's output PES byte stream into 188-byte TS
// packets. It regenerates PUSI and continuity counters, preserves meaningful
// adaptation metadata, adds stuffing to partial packets, and queues completed
// packets until TakePackets. At most one TS payload is pending.
type TSPacketizer struct {
	pid     uint16
	cc      uint8
	current pendingTSPacket
	pesOpen bool
	packets []*astits.Packet
}

func NewTSPacketizer(pid uint16) *TSPacketizer {
	return &TSPacketizer{pid: pid}
}

// SetContinuityCounter sets the counter that the next payload-bearing output packet will use.
func (w *TSPacketizer) SetContinuityCounter(cc uint8) {
	w.cc = cc
}

// BeginPES validates and writes a PES header, marking the next emitted payload
// packet as the start of the PES.
func (w *TSPacketizer) BeginPES(header []byte) error {
	if w.pesOpen {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: previous PES is still open",
			w.pid,
		)
	}
	if len(header) < 6 {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: PES header is too short: %d",
			w.pid,
			len(header),
		)
	}
	if header[0] != 0 || header[1] != 0 || header[2] != 1 {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: PES start code prefix missing",
			w.pid,
		)
	}
	if w.current.payloadLen > 0 || w.current.pusi {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: pending payload outside PES",
			w.pid,
		)
	}
	w.current.pusi = true
	w.pesOpen = true
	return w.writePESBytes(header)
}

// WritePESPayload appends elementary-stream bytes to the open PES
func (w *TSPacketizer) WritePESPayload(payload []byte) error {
	if !w.pesOpen {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: write outside PES",
			w.pid,
		)
	}
	return w.writePESBytes(payload)
}

// writePESBytes appends arbitrary PES bytes to the current output TS packet.
// One call may fill several packets; several calls may share one packet.
func (w *TSPacketizer) writePESBytes(data []byte) error {
	for len(data) > 0 {
		// Check cap because a carried adaptation field may reduce maximum payload
		capacity, err := payloadCapacity(w.current.adaptation)
		if err != nil {
			return fmt.Errorf("TS packetizer PID 0x%04X: %w", w.pid, err)
		}
		// A payload-bearing TS packet must have room for at least one payload byte
		if capacity == 0 {
			return fmt.Errorf(
				"TS packetizer PID 0x%04X: adaptation field leaves no payload capacity",
				w.pid,
			)
		}
		// This is mainly a defensive state check. A packet that was made full by
		// earlier writes must be emitted before any new bytes are assigned to it
		if w.current.payloadLen == capacity {
			if err := w.flushPayloadPacket(); err != nil {
				return err
			}
			continue
		}

		// Copy only what fits after bytes already buffered in current
		//
		//	bytes to copy = min(input left, capacity - payloadLen)
		n := min(len(data), capacity-w.current.payloadLen)
		copy(
			w.current.payload[w.current.payloadLen:],
			data[:n],
		)
		w.current.payloadLen += n
		data = data[n:]
		// Full packets can be emitted immediately. Partial packets wait for more
		// PES bytes or EndPES, which will fill the gap with adaptation stuffing
		if w.current.payloadLen == capacity {
			if err := w.flushPayloadPacket(); err != nil {
				return err
			}
		}
	}
	return nil
}

// EndPES closes the current PES. Any final partial payload packet is
// emitted immediately and padded through its adaptation field to 188 bytes.
func (w *TSPacketizer) EndPES() error {
	if !w.pesOpen {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: no open PES",
			w.pid,
		)
	}
	if w.current.payloadLen > 0 {
		if err := w.flushPayloadPacket(); err != nil {
			return err
		}
		w.pesOpen = false
		return nil
	}
	// A PES with no buffered bytes must not produce an empty PUSI payload packet
	w.current.pusi = false
	// Metadata may have arrived before the PES ended without any following PES
	// bytes. Preserve it as a separate adaptation-only packet instead of dropping
	// PCR or another timing signal
	if w.current.adaptation != nil {
		if err := w.flushPendingAdaptationOnly(); err != nil {
			return err
		}
	}
	w.pesOpen = false
	return nil
}

// TakePackets transfers all completed TS packets to the caller.
func (w *TSPacketizer) TakePackets() []*astits.Packet {
	packets := w.packets
	w.packets = nil
	return packets
}

// SetNextPacketAdaptationField schedules meaningful metadata for the next
// payload packet. The packetizer retains field; the caller must clone it first
// when the source may be reused or changed.
func (w *TSPacketizer) SetNextPacketAdaptationField(
	field *astits.PacketAdaptationField,
) error {
	if !astits.HasAdaptationFieldData(field) {
		return nil
	}
	// Two source adaptation fields must never be merged. First emit the older
	// field with its pending payload, or by itself if no payload followed it
	if w.current.adaptation != nil {
		if w.current.payloadLen > 0 {
			if err := w.flushPayloadPacket(); err != nil {
				return err
			}
		} else if err := w.flushPendingAdaptationOnly(); err != nil {
			return err
		}
	}

	capacity, err := payloadCapacity(field)
	// SetNextPacketAdaptationField is for a packet that has payload. Metadata consuming
	// the complete body cannot be represented on such an output packet
	if err != nil || capacity == 0 {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: adaptation field leaves no payload capacity",
			w.pid,
		)
	}
	// Bytes already buffered came before this source adaptation field. Flush them
	// when they would leave no room for at least one following byte, ensuring PCR
	// and other metadata are not attached entirely to earlier payload
	if w.current.payloadLen >= capacity {
		if err := w.flushPayloadPacket(); err != nil {
			return err
		}
	}
	// The next PES write now fills a packet whose reduced capacity accounts for this metadata
	w.current.adaptation = field
	return nil
}

// WriteAdaptationOnly preserves an input TS packet that has adaptation metadata
// but no payload. It remains a separate output packet and does not advance the
// writer's payload continuity sequence.
func (w *TSPacketizer) WriteAdaptationOnly(
	field *astits.PacketAdaptationField,
) error {
	// Ignore packets whose adaptation field contains only disposable stuffing
	if !astits.HasAdaptationFieldData(field) {
		return nil
	}
	// Emit older buffered state first to preserve stream order around this
	// standalone timing/metadata packet
	if w.current.payloadLen > 0 {
		if err := w.flushPayloadPacket(); err != nil {
			return err
		}
	} else if w.current.adaptation != nil {
		if err := w.flushPendingAdaptationOnly(); err != nil {
			return err
		}
	}
	return w.writeAdaptationOnly(field)
}

func (w *TSPacketizer) Flush() error {
	// Silently writing these bytes would hide a missing PESEnd and make the final
	// PES boundary ambiguous, so an open unit is an error
	if w.pesOpen || w.current.payloadLen > 0 || w.current.pusi {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: PES is still open",
			w.pid,
		)
	}
	if w.current.adaptation != nil {
		return w.flushPendingAdaptationOnly()
	}
	return nil
}

// flushPayloadPacket materializes current as exactly one 188-byte TS packet,
// queues it, advances payload continuity, then clears the pending state.
func (w *TSPacketizer) flushPayloadPacket() error {
	if w.current.payloadLen == 0 {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: no payload to flush",
			w.pid,
		)
	}

	packet := &astits.Packet{
		Header: astits.PacketHeader{
			ContinuityCounter:         w.cc,
			HasPayload:                true,
			PayloadUnitStartIndicator: w.current.pusi,
			PID:                       w.pid,
		},
		Payload: append(
			[]byte(nil),
			w.current.payload[:w.current.payloadLen]...,
		),
	}
	remaining := TSPacketPayloadCapacity - w.current.payloadLen
	if remaining > 0 {
		var err error
		packet.Header.HasAdaptationField = true
		if w.current.adaptation == nil {
			// No source metadata: create a field consisting entirely of stuffing
			packet.AdaptationField, err = astits.NewStuffingAdaptationField(remaining)
		} else {
			packet.AdaptationField, err = astits.AdaptationFieldWithSize(w.current.adaptation, remaining)
		}
		if err != nil {
			return fmt.Errorf(
				"TS packetizer PID 0x%04X: prepare adaptation field: %w",
				w.pid,
				err,
			)
		}
	}
	w.packets = append(w.packets, packet)
	w.cc = (w.cc + 1) & 0x0F
	w.current.reset()
	return nil
}

// flushPendingAdaptationOnly emits carried metadata when no payload bytes ever
// followed it. Does not advance the continuity counter.
func (w *TSPacketizer) flushPendingAdaptationOnly() error {
	if err := w.writeAdaptationOnly(w.current.adaptation); err != nil {
		return err
	}
	w.current.adaptation = nil
	return nil
}

// writeAdaptationOnly emits one TS packet whose complete 184-byte body is an
// adaptation field.
func (w *TSPacketizer) writeAdaptationOnly(
	field *astits.PacketAdaptationField,
) error {
	adaptation, err := astits.AdaptationFieldWithSize(field, TSPacketPayloadCapacity)
	if err != nil {
		return fmt.Errorf(
			"TS packetizer PID 0x%04X: prepare adaptation-only field: %w",
			w.pid,
			err,
		)
	}
	w.packets = append(w.packets, &astits.Packet{
		Header: astits.PacketHeader{
			ContinuityCounter:  (w.cc + 15) & 0x0F,
			HasAdaptationField: true,
			PID:                w.pid,
		},
		AdaptationField: adaptation,
	})
	return nil
}
