package packets

import "fmt"

type PESHandler interface {
	PESHeader([]byte) error
	PESPayload(payload []byte) error
	PESEnd() error
}

// PESCollector reconstructs PES framing for one elementary PID from successive
// TS payloads. It waits for PUSI, buffers only the possibly split PES header,
// validates declared lengths, and streams elementary bytes to a PESHandler.
type PESCollector struct {
	active           bool // Are we waiting for header/payload after we saw a PUSI
	header           []byte
	headerLength     int // 9 + PES_header_data_length (basically everything before the actual stream data)
	payloadRemaining int // Amount of actual stream data remaining (e.g. H.264). -1 for length == 0 (based on the packet length field)
}

func (m *PESCollector) Active() bool {
	return m.active
}

func (m *PESCollector) Consume(pusi bool, payload []byte, handler PESHandler) error {
	if pusi {
		if m.active {
			if err := m.finish(handler); err != nil {
				return err
			}
		}
		m.start()
	}
	if !m.active {
		return nil
	}

	for len(payload) > 0 {
		if !m.active {
			return fmt.Errorf("PES contains bytes after its declared length")
		}
		if m.headerLength == 0 || len(m.header) < m.headerLength {
			n, err := m.consumeHeader(payload)
			if err != nil {
				return err
			}
			payload = payload[n:]
			if m.headerLength == 0 || len(m.header) < m.headerLength {
				if len(payload) == 0 {
					return nil
				}
				continue
			}
			if err := handler.PESHeader(append([]byte(nil), m.header...)); err != nil {
				return err
			}
			if m.payloadRemaining == 0 {
				if err := m.finish(handler); err != nil {
					return err
				}
			}
			continue
		}

		n := len(payload)
		if m.payloadRemaining >= 0 && n > m.payloadRemaining {
			n = m.payloadRemaining
		}
		if n == 0 {
			return fmt.Errorf("PES contains bytes after its declared length")
		}
		if err := handler.PESPayload(payload[:n]); err != nil {
			return err
		}
		payload = payload[n:]
		if m.payloadRemaining >= 0 {
			m.payloadRemaining -= n
			if m.payloadRemaining == 0 {
				if err := m.finish(handler); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *PESCollector) Flush(handler PESHandler) error {
	if !m.active {
		return nil
	}
	if m.headerLength == 0 || len(m.header) < m.headerLength {
		return fmt.Errorf("truncated PES header")
	}
	if m.payloadRemaining > 0 {
		return fmt.Errorf("truncated PES payload: %d bytes missing", m.payloadRemaining)
	}
	return m.finish(handler)
}

func (m *PESCollector) start() {
	m.active = true
	m.header = m.header[:0]
	m.headerLength = 0
	m.payloadRemaining = -1
}

func (m *PESCollector) finish(handler PESHandler) error {
	if m.headerLength == 0 || len(m.header) < m.headerLength {
		return fmt.Errorf("new PES starts before previous PES header is complete")
	}
	if m.payloadRemaining > 0 {
		return fmt.Errorf("new PES starts with %d bytes missing from previous PES", m.payloadRemaining)
	}
	m.active = false
	m.header = m.header[:0]
	m.headerLength = 0
	m.payloadRemaining = -1
	return handler.PESEnd()
}

func (m *PESCollector) consumeHeader(payload []byte) (int, error) {
	needed := 9 // To grab PES_header_data_length
	if m.headerLength > 0 {
		// If the header was splitted between packets and we already have smth in the buffer
		needed = m.headerLength
	}
	n := min(len(payload), needed-len(m.header))
	m.header = append(m.header, payload[:n]...)

	// Start code is always these 3 bytes: 00 00 01
	if len(m.header) >= 3 && (m.header[0] != 0 || m.header[1] != 0 || m.header[2] != 1) {
		return 0, fmt.Errorf("PES start code prefix missing")
	}

	// Not enough yet
	if len(m.header) < 9 {
		return n, nil
	}

	/*
		index  bytes                         included in PES_packet_length?
		0..2   00 00 01                      n
		3      stream_id                     n
		4..5   PES_packet_length             field itself — n
		6      flags                         y
		7      flags                         y
		8      PES_header_data_length = N    y     (length of the next optional header)
		9..    optional header, N bytes      y
		...    AAC/H.264 payload             y
	*/

	if m.headerLength == 0 {
		headerDataLength := int(m.header[8])
		m.headerLength = 9 + headerDataLength
		packetLength := int(m.header[4])<<8 | int(m.header[5])
		if packetLength == 0 {
			m.payloadRemaining = -1
			return n, nil
		}
		// packetLength + 6 is whole PES (header + payload)
		m.payloadRemaining = packetLength + 6 - m.headerLength
		if m.payloadRemaining < 0 {
			return 0, fmt.Errorf("PES packet length %d shorter than header", packetLength)
		}
	}
	return n, nil
}
