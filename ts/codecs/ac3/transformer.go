package ac3

import (
	"fmt"

	"github.com/bldsoft/mpegenc/sampleaes"
	"github.com/bldsoft/mpegenc/ts/internal/pmtsignal"
	"github.com/bldsoft/mpegenc/ts/packets"
)

const (
	ac3HeaderSize = 5
	ac3SetupSize  = 10
	ac3ClearLead  = 16
)

var frameSizeWords = [38][3]uint16{
	{64, 69, 96},
	{64, 70, 96},
	{80, 87, 120},
	{80, 88, 120},
	{96, 104, 144},
	{96, 105, 144},
	{112, 121, 168},
	{112, 122, 168},
	{128, 139, 192},
	{128, 140, 192},
	{160, 174, 240},
	{160, 175, 240},
	{192, 208, 288},
	{192, 209, 288},
	{224, 243, 336},
	{224, 244, 336},
	{256, 278, 384},
	{256, 279, 384},
	{320, 348, 480},
	{320, 349, 480},
	{384, 417, 576},
	{384, 418, 576},
	{448, 487, 672},
	{448, 488, 672},
	{512, 557, 768},
	{512, 558, 768},
	{640, 696, 960},
	{640, 697, 960},
	{768, 835, 1152},
	{768, 836, 1152},
	{896, 975, 1344},
	{896, 976, 1344},
	{1024, 1114, 1536},
	{1024, 1115, 1536},
	{1152, 1253, 1728},
	{1152, 1254, 1728},
	{1280, 1393, 1920},
	{1280, 1394, 1920},
}

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
		return fmt.Errorf("AC-3 transformer: previous PES is still open")
	}
	if len(header) < 6 {
		return fmt.Errorf("AC-3 transformer: PES header is too short: %d", len(header))
	}
	t.pes = append(t.pes, pendingPES{header: append([]byte(nil), header...)})
	t.inputPESOpen = true
	return nil
}

func (t *Transformer) PESPayload(payload []byte) error {
	if !t.inputPESOpen {
		return fmt.Errorf("AC-3 transformer: payload outside PES")
	}
	t.buffer = append(t.buffer, payload...)
	t.pes[len(t.pes)-1].bytes += len(payload)
	return t.processFrames()
}

func (t *Transformer) PESEnd() error {
	if !t.inputPESOpen {
		return fmt.Errorf("AC-3 transformer: no open PES")
	}
	t.pes[len(t.pes)-1].ended = true
	t.inputPESOpen = false
	return t.finishPES()
}

func (t *Transformer) Flush() error {
	if t.inputPESOpen {
		return fmt.Errorf("AC-3 transformer: PES is still open")
	}
	if err := t.processFrames(); err != nil {
		return err
	}
	if len(t.buffer) != 0 {
		return fmt.Errorf("AC-3 transformer: truncated syncframe")
	}
	if err := t.finishPES(); err != nil {
		return err
	}
	if len(t.pes) != 0 {
		return fmt.Errorf("AC-3 transformer: incomplete PES")
	}
	return nil
}

func (t *Transformer) processFrames() error {
	for {
		if len(t.buffer) < ac3HeaderSize {
			return nil
		}
		if t.buffer[0] != 0x0B || t.buffer[1] != 0x77 {
			return fmt.Errorf("AC-3 transformer: syncword missing")
		}
		fscod := t.buffer[4] >> 6
		frmsizecod := t.buffer[4] & 0x3F
		if fscod > 2 || frmsizecod > 37 {
			return fmt.Errorf("AC-3 transformer: invalid frame size code")
		}
		frameSize := int(frameSizeWords[frmsizecod][fscod]) * 2
		if len(t.buffer) < ac3SetupSize {
			return nil
		}
		if t.buffer[5]>>3 > 8 {
			return fmt.Errorf("AC-3 transformer: unsupported bitstream id")
		}
		if !t.configSent {
			var setup [10]byte
			copy(setup[:], t.buffer)
			if err := t.signal(patchPMT(setup)); err != nil {
				return err
			}
			t.configSent = true
		}
		if len(t.buffer) < frameSize {
			return nil
		}

		frame := t.buffer[:frameSize]
		if frameSize > ac3ClearLead {
			protectedSize := (frameSize - ac3ClearLead) / 16 * 16
			if protectedSize > 0 {
				if err := t.block.Reset(); err != nil {
					return err
				}
				if err := t.block.CryptBlocks(frame[ac3ClearLead : ac3ClearLead+protectedSize]); err != nil {
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
			return fmt.Errorf("AC-3 transformer: missing PES for syncframe payload")
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
