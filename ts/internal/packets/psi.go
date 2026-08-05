package packets

import "fmt"

// psiSectionCollector reconstructs complete PSI sections from consecutive TS
// payloads belonging to one PSI PID.
type psiSectionCollector struct {
	buf []byte
}

// Consume adds one TS payload and returns every complete PSI section found in it.
// Returned sections exclude the pointer_field and any TS-packet stuffing bytes.
func (c *psiSectionCollector) Consume(pusi bool, payload []byte) ([][]byte, error) {
	if !pusi {
		return c.append(payload)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("PSI payload starts without pointer field")
	}

	pointerField := int(payload[0])
	if pointerField > len(payload)-1 {
		return nil, fmt.Errorf("PSI pointer field %d exceeds payload size %d", pointerField, len(payload)-1)
	}

	var sections [][]byte
	if len(c.buf) > 0 {
		// Bytes before the next section start can complete the previous one
		completed, err := c.append(payload[1 : 1+pointerField])
		if err != nil {
			return nil, err
		}
		sections = append(sections, completed...)

		// The new section cannot continue an incomplete old section
		c.buf = nil
	}

	completed, err := c.append(payload[1+pointerField:])
	if err != nil {
		return nil, err
	}
	return append(sections, completed...), nil
}

func (c *psiSectionCollector) append(payload []byte) ([][]byte, error) {
	c.buf = append(c.buf, payload...)

	var sections [][]byte
	for {
		if len(c.buf) == 0 {
			return sections, nil
		}
		// 0xFF marks unused payload bytes after the last PSI section
		if c.buf[0] == 0xFF {
			c.buf = nil
			return sections, nil
		}
		if len(c.buf) < 3 {
			return sections, nil
		}

		sectionLength := int(c.buf[1]&0x0F)<<8 | int(c.buf[2])
		if sectionLength > 1021 {
			return nil, fmt.Errorf("invalid PSI section length %d", sectionLength)
		}
		totalLength := 3 + sectionLength
		if len(c.buf) < totalLength {
			return sections, nil
		}

		section := append([]byte(nil), c.buf[:totalLength]...)
		c.buf = c.buf[totalLength:]
		sections = append(sections, section)
	}
}
