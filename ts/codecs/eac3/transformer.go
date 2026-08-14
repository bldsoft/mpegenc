package eac3

import (
	"fmt"

	"github.com/bldsoft/mpegenc/sampleaes"
	"github.com/bldsoft/mpegenc/ts/internal/pmtsignal"
	"github.com/bldsoft/mpegenc/ts/packets"
)

const (
	eac3HeaderSize = 7
	eac3ClearLead  = 16
)

var (
	sampleRates = [4]int{48000, 44100, 32000}
	frameBlocks = [4]int{1, 2, 3, 6}
)

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

type syncframeHeader struct {
	frameType  byte
	frameSize  int
	sampleRate int
	blocks     int
	fscod      byte
	bsid       byte
	acmod      byte
	lfeon      byte
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
		return fmt.Errorf("E-AC-3 transformer: previous PES is still open")
	}
	if len(header) < 6 {
		return fmt.Errorf("E-AC-3 transformer: PES header is too short: %d", len(header))
	}
	t.pes = append(t.pes, pendingPES{header: append([]byte(nil), header...)})
	t.inputPESOpen = true
	return nil
}

func (t *Transformer) PESPayload(payload []byte) error {
	if !t.inputPESOpen {
		return fmt.Errorf("E-AC-3 transformer: payload outside PES")
	}
	t.buffer = append(t.buffer, payload...)
	t.pes[len(t.pes)-1].bytes += len(payload)
	return t.processFrames()
}

func (t *Transformer) PESEnd() error {
	if !t.inputPESOpen {
		return fmt.Errorf("E-AC-3 transformer: no open PES")
	}
	t.pes[len(t.pes)-1].ended = true
	t.inputPESOpen = false
	return t.finishPES()
}

func (t *Transformer) Flush() error {
	if t.inputPESOpen {
		return fmt.Errorf("E-AC-3 transformer: PES is still open")
	}
	if err := t.processFrames(); err != nil {
		return err
	}
	if len(t.buffer) != 0 {
		return fmt.Errorf("E-AC-3 transformer: truncated syncframe")
	}
	if err := t.finishPES(); err != nil {
		return err
	}
	if len(t.pes) != 0 {
		return fmt.Errorf("E-AC-3 transformer: incomplete PES")
	}
	return nil
}

func (t *Transformer) processFrames() error {
	for {
		if len(t.buffer) < eac3HeaderSize {
			return nil
		}
		header, err := parseSyncframeHeader(t.buffer)
		if err != nil {
			return err
		}
		if !t.configSent {
			if header.frameType != 0 && header.frameType != 2 {
				return fmt.Errorf("E-AC-3 transformer: independent syncframe required first")
			}
			if err := t.signal(patchPMT(header.setup())); err != nil {
				return err
			}
			t.configSent = true
		}
		if len(t.buffer) < header.frameSize {
			return nil
		}

		if header.frameType == 0 || header.frameType == 2 {
			if err := t.block.Reset(); err != nil {
				return err
			}
		}

		frame := t.buffer[:header.frameSize]
		if header.frameSize > eac3ClearLead {
			protectedSize := (header.frameSize - eac3ClearLead) / 16 * 16
			if protectedSize > 0 {
				if err := t.block.CryptBlocks(frame[eac3ClearLead : eac3ClearLead+protectedSize]); err != nil {
					return err
				}
			}
		}
		if err := t.write(frame); err != nil {
			return err
		}
		if len(t.buffer) == header.frameSize {
			t.buffer = t.buffer[:0]
		} else {
			t.buffer = t.buffer[header.frameSize:]
		}
	}
}

func parseSyncframeHeader(data []byte) (syncframeHeader, error) {
	if data[0] != 0x0B || data[1] != 0x77 {
		return syncframeHeader{}, fmt.Errorf("E-AC-3 transformer: syncword missing")
	}
	frameType := data[2] >> 6
	if frameType == 3 {
		return syncframeHeader{}, fmt.Errorf("E-AC-3 transformer: reserved frame type")
	}
	frameSize := (((int(data[2]&0x07) << 8) | int(data[3])) + 1) * 2
	if frameSize < eac3HeaderSize {
		return syncframeHeader{}, fmt.Errorf("E-AC-3 transformer: invalid frame size %d", frameSize)
	}
	fscod := data[4] >> 6
	blocks := 6
	sampleRate := 0
	if fscod == 3 {
		fscod2 := data[4] >> 4 & 0x03
		if fscod2 == 3 {
			return syncframeHeader{}, fmt.Errorf("E-AC-3 transformer: invalid sample rate code")
		}
		sampleRate = sampleRates[fscod2] / 2
	} else {
		blocks = frameBlocks[data[4]>>4&0x03]
		sampleRate = sampleRates[fscod]
	}
	bsid := data[5] >> 3
	if bsid < 11 || bsid > 16 {
		return syncframeHeader{}, fmt.Errorf("E-AC-3 transformer: invalid bitstream id %d", bsid)
	}
	return syncframeHeader{
		frameType:  frameType,
		frameSize:  frameSize,
		sampleRate: sampleRate,
		blocks:     blocks,
		fscod:      fscod,
		bsid:       bsid,
		acmod:      data[4] >> 1 & 0x07,
		lfeon:      data[4] & 0x01,
	}, nil
}

func (h syncframeHeader) setup() [5]byte {
	dataRate := h.frameSize * 8 * h.sampleRate / (h.blocks * 256) / 1000
	return [5]byte{
		byte(dataRate >> 5),
		byte(dataRate << 3),
		h.fscod<<6 | h.bsid<<1,
		h.acmod<<1 | h.lfeon,
		0,
	}
}

func (t *Transformer) write(data []byte) error {
	for len(data) > 0 {
		if len(t.pes) == 0 || t.pes[0].bytes == 0 {
			return fmt.Errorf("E-AC-3 transformer: missing PES for syncframe payload")
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
