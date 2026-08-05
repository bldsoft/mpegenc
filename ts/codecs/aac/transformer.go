package aac

import (
	"fmt"

	"mpegenc/sampleaes"
	"mpegenc/ts/internal/pmtsignal"
	"mpegenc/ts/packets"
)

const adtsHeaderSize = 7

type Transformer struct {
	next   packets.PESHandler
	block  sampleaes.BlockCryptor
	signal pmtsignal.Signal

	inputPESOpen bool
	buffer       []byte
	pes          []pendingPES
	configSent   bool
}

type pendingPES struct {
	header  []byte
	bytes   int
	ended   bool
	started bool
}

func NewTransformer(
	next packets.PESHandler,
	block sampleaes.BlockCryptor,
	signal pmtsignal.Signal,
) *Transformer {
	return &Transformer{next: next, block: block, signal: signal}
}

func (t *Transformer) PESHeader(header []byte) error {
	if t.inputPESOpen {
		return fmt.Errorf("AAC transformer: previous PES is still open")
	}
	if len(header) < 6 {
		return fmt.Errorf("AAC transformer: PES header is too short: %d", len(header))
	}
	t.pes = append(t.pes, pendingPES{header: append([]byte(nil), header...)})
	t.inputPESOpen = true
	return nil
}

func (t *Transformer) PESPayload(payload []byte) error {
	if !t.inputPESOpen {
		return fmt.Errorf("AAC transformer: payload outside PES")
	}
	t.buffer = append(t.buffer, payload...)
	t.pes[len(t.pes)-1].bytes += len(payload)
	return t.processFrames()
}

func (t *Transformer) PESEnd() error {
	if !t.inputPESOpen {
		return fmt.Errorf("AAC transformer: no open PES")
	}
	t.pes[len(t.pes)-1].ended = true
	t.inputPESOpen = false
	return t.finishPES()
}

func (t *Transformer) Flush() error {
	if t.inputPESOpen {
		return fmt.Errorf("AAC transformer: PES is still open")
	}
	if err := t.processFrames(); err != nil {
		return err
	}
	if len(t.buffer) != 0 {
		return fmt.Errorf("AAC transformer: truncated ADTS frame")
	}
	if err := t.finishPES(); err != nil {
		return err
	}
	if len(t.pes) != 0 {
		return fmt.Errorf("AAC transformer: incomplete PES")
	}
	return nil
}

func (t *Transformer) processFrames() error {
	for {
		if len(t.buffer) < adtsHeaderSize {
			return nil
		}
		if t.buffer[0] != 0xFF || t.buffer[1]&0xF0 != 0xF0 {
			return fmt.Errorf("AAC transformer: ADTS syncword missing")
		}
		headerSize := adtsHeaderSize
		if t.buffer[1]&1 == 0 {
			headerSize = 9
		}
		if len(t.buffer) < headerSize {
			return nil
		}
		if !t.configSent {
			profile := (t.buffer[2] >> 6) & 0x03
			samplingFrequencyIndex := (t.buffer[2] >> 2) & 0x0F
			channelConfiguration := (t.buffer[2]&0x01)<<2 | t.buffer[3]>>6
			audioObjectType := profile + 1
			// TODO Add support for HE-AAC, HE-AACv2
			if err := t.signal(patchPMT([2]byte{
				audioObjectType<<3 | samplingFrequencyIndex>>1,
				samplingFrequencyIndex<<7 | channelConfiguration<<3,
			})); err != nil {
				return err
			}
			t.configSent = true
		}
		frameSize := int(t.buffer[3]&0x03)<<11 |
			int(t.buffer[4])<<3 |
			int(t.buffer[5]>>5)
		if frameSize < headerSize {
			return fmt.Errorf("AAC transformer: invalid ADTS frame length %d", frameSize)
		}
		if len(t.buffer) < frameSize {
			return nil
		}

		frame := t.buffer[:frameSize]
		protectedOffset := headerSize + 16
		if protectedOffset < frameSize {
			protectedSize := (frameSize - protectedOffset) / 16 * 16
			if protectedSize > 0 {
				if err := t.block.Reset(); err != nil {
					return err
				}
				if err := t.block.CryptBlocks(frame[protectedOffset : protectedOffset+protectedSize]); err != nil {
					return err
				}
			}
		}
		if err := t.write(frame); err != nil {
			return err
		}
		t.buffer = t.buffer[frameSize:]
	}
}

func (t *Transformer) write(data []byte) error {
	for len(data) > 0 {
		if len(t.pes) == 0 || t.pes[0].bytes == 0 {
			return fmt.Errorf("AAC transformer: missing PES for ADTS payload")
		}
		pes := &t.pes[0]
		if !pes.started {
			if err := t.next.PESHeader(pes.header); err != nil {
				return err
			}
			pes.started = true
		}
		n := min(len(data), pes.bytes)
		if err := t.next.PESPayload(data[:n]); err != nil {
			return err
		}
		pes.bytes -= n
		data = data[n:]
		if err := t.finishPES(); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transformer) finishPES() error {
	for len(t.pes) > 0 && t.pes[0].ended && t.pes[0].bytes == 0 {
		if !t.pes[0].started {
			if err := t.next.PESHeader(t.pes[0].header); err != nil {
				return err
			}
		}
		if err := t.next.PESEnd(); err != nil {
			return err
		}
		t.pes[0] = pendingPES{}
		t.pes = t.pes[1:]
	}
	return nil
}
