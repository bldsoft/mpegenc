package avc

import (
	"bytes"
	"fmt"

	"github.com/bldsoft/mpegenc/sampleaes"
	"github.com/bldsoft/mpegenc/ts/internal/pmtsignal"
	"github.com/bldsoft/mpegenc/ts/packets"
)

const (
	// the first encryption decision needs 32 + 16 + 1 bytes of lookahead.
	avcProbeSize = 49
	avcClearLead = 32
	avcBlockSize = 16

	avcPatternSkipSize = 9 * avcBlockSize
)

var (
	annexBStartCode = []byte{0, 0, 1}

	zeroBytes [256]byte
)

// Transformer applies AVC Sample-AES while preserving the original PES
// boundaries. Input may split Annex-B start codes, the 49-byte initial probe,
// or a 16-byte encryption block across any number of PES payload calls.
//
// Bytes delayed by those operations remain accounted to their source PES in
// pes. When the bytes are eventually written, write splits them by that queue,
// emits the corresponding PES boundaries, and starts queued PES headers.
type Transformer struct {
	next  packets.PESHandler
	block sampleaes.BlockCryptor

	inputPESOpen bool
	// pes contains input PES records that have not been completely emitted.
	// Usually it has one entry, but delayed AVC bytes can keep an older PES
	// queued after the next input PES has already started
	pes []pendingPES

	// nalState describes how bytes after the latest Annex-B start code are
	// interpreted. zeroRun holds trailing zeros whose meaning is unresolved:
	// they may be NAL data or the prefix of a start code in the next chunk.
	nalState avcNALState
	zeroRun  int

	nalEncrypted bool
	// pattern serves both as the 49-byte initial probe and, after the probe,
	// as the pending 16-byte encryption block
	pattern    [avcProbeSize]byte
	patternLen int
	// skip is the number of clear bytes remaining before the next AES block
	skip int

	escaper ebspEscaper
	// scratch holds an escaped output slice
	scratch []byte
}

type pendingPES struct {
	header []byte
	// bytes counts source elementary-stream bytes received for this PES but
	// not yet passed to next. It does not count EPB bytes inserted
	// by the escaper
	bytes int
	// ended records that PESEnd was received on input. The output end is sent
	// only after bytes reaches zero
	ended bool
	// started records that the output PESHeader has already been sent
	started bool
}

type avcNALState uint8

const (
	// No Annex-B start code has been seen, or the previous NAL has finished
	avcNALStateNone avcNALState = iota
	// A start code was seen and the next byte must be interpreted as NAL header
	avcNALStateHeader
	// This NAL is copied unchanged
	avcNALStatePassthrough
	// This is an eligible type 1/5 NAL processed with the Sample-AES pattern
	avcNALStateProtected
)

func NewTransformer(
	next packets.PESHandler,
	block sampleaes.BlockCryptor,
	signal pmtsignal.Signal,
) (*Transformer, error) {
	if err := signal(patchPMT); err != nil {
		return nil, err
	}
	return newTransformer(next, block), nil
}

func newTransformer(
	next packets.PESHandler,
	block sampleaes.BlockCryptor,
) *Transformer {
	return &Transformer{
		next:  next,
		block: block,
	}
}

func (t *Transformer) PESHeader(header []byte) error {
	if t.inputPESOpen {
		return fmt.Errorf("AVC transformer: previous PES is still open")
	}
	if len(header) < 6 {
		return fmt.Errorf("AVC transformer: PES header is too short: %d", len(header))
	}

	// Set pes length to 00 00 which is unbounded length and is valid. However this causes problems with FFmpeg.
	// It incorrectly decodes last packets of the chunk and screams warnings. TODO: write valid pes length?
	outputHeader := append([]byte(nil), header...)
	outputHeader[4] = 0
	outputHeader[5] = 0
	pes := pendingPES{header: outputHeader}

	if len(t.pes) == 0 {
		if err := t.next.PESHeader(outputHeader); err != nil {
			return err
		}
		pes.started = true
	}
	t.pes = append(t.pes, pes)
	t.inputPESOpen = true
	return nil
}

func (t *Transformer) PESPayload(payload []byte) error {
	if !t.inputPESOpen {
		return fmt.Errorf("AVC transformer: payload outside PES")
	}

	t.pes[len(t.pes)-1].bytes += len(payload)

	if t.zeroRun > 0 {
		n := 0
		for n < len(payload) && payload[n] == 0 {
			n++
		}
		t.zeroRun += n
		payload = payload[n:]
		if len(payload) == 0 {
			return nil
		}
		if payload[0] == 1 && t.zeroRun >= 2 {
			// The complete zero run plus this 01 is start-code framing, not NAL
			// data, so finish the old NAL before writing those bytes unchanged
			if t.nalState != avcNALStateNone {
				if err := t.finishNAL(); err != nil {
					return err
				}
			}
			if err := t.writeZeros(t.zeroRun, false); err != nil {
				return err
			}
			t.zeroRun = 0
			if err := t.write(payload[:1], false); err != nil {
				return err
			}
			t.beginNAL()
			payload = payload[1:]
		} else {
			// The run was ordinary NAL data. It must re-enter writeNAL so it is
			// counted in the Sample-AES pattern and escaped when appropriate
			if t.nalState == avcNALStateNone {
				return fmt.Errorf("AVC transformer: bytes before Annex-B start code")
			}
			if err := t.writeNALZeros(t.zeroRun); err != nil {
				return err
			}
			t.zeroRun = 0
		}
	}

	for len(payload) > 0 {
		startCode := bytes.Index(payload, annexBStartCode)
		if startCode < 0 {
			end := len(payload)
			for end > 0 && payload[end-1] == 0 {
				end--
			}
			// Everything except trailing zeros is definitely NAL data
			if end > 0 {
				if err := t.writeNAL(payload[:end]); err != nil {
					return err
				}
			}
			t.zeroRun = len(payload) - end
			return nil
		}

		start := startCode
		for start > 0 && payload[start-1] == 0 {
			start--
		}
		if start > 0 {
			if err := t.writeNAL(payload[:start]); err != nil {
				return err
			}
		}
		if t.nalState != avcNALStateNone {
			if err := t.finishNAL(); err != nil {
				return err
			}
		}
		end := startCode + len(annexBStartCode)
		if err := t.write(payload[start:end], false); err != nil {
			return err
		}
		t.beginNAL()
		payload = payload[end:]
	}
	return nil
}

func (t *Transformer) PESEnd() error {
	if !t.inputPESOpen {
		return fmt.Errorf("AVC transformer: no open PES")
	}

	// Ending the input PES does not necessarily end it downstream. Its final
	// bytes may still be held by zeroRun or pattern; finishPES closes it when
	// those bytes have later reduced pendingPES.bytes to zero
	t.pes[len(t.pes)-1].ended = true
	t.inputPESOpen = false
	return t.finishPES()
}

func (t *Transformer) Flush() error {
	if t.inputPESOpen {
		return fmt.Errorf("AVC transformer: PES is still open")
	}
	if t.nalState != avcNALStateNone {
		if err := t.finishNAL(); err != nil {
			return err
		}
	}

	// No following byte exists to turn a final zero run into a start code.
	// Annex-B permits trailing zero bytes, so emit them unchanged after the NAL
	if t.zeroRun > 0 {
		if err := t.writeZeros(t.zeroRun, false); err != nil {
			return err
		}
		t.zeroRun = 0
	}
	return t.finishPES()
}

func (t *Transformer) writeNAL(data []byte) error {
	if t.nalState == avcNALStateNone {
		return fmt.Errorf("AVC transformer: bytes before Annex-B start code")
	}

	if t.nalState == avcNALStateHeader {
		nalType := data[0] & 0x1F
		if t.block != nil && (nalType == 1 || nalType == 5) {
			t.nalState = avcNALStateProtected
		} else {
			t.nalState = avcNALStatePassthrough
		}
	}

	if t.nalState == avcNALStatePassthrough {
		return t.write(data, false)
	}

	// Buffer the first 49 bytes before changing anything. A NAL with at most
	// 48 bytes must remain clear. Byte 49 proves that the first 16-byte island
	// at offsets [32:48] is not the final block and may therefore be encrypted
	if !t.nalEncrypted {
		n := copy(t.pattern[t.patternLen:], data)
		t.patternLen += n
		data = data[n:]
		if t.patternLen < len(t.pattern) {
			return nil
		}
		if err := t.block.Reset(); err != nil {
			return err
		}
		if err := t.block.CryptBlocks(t.pattern[avcClearLead : avcClearLead+avcBlockSize]); err != nil {
			return err
		}
		if err := t.write(t.pattern[:], true); err != nil {
			return err
		}
		t.patternLen = 0
		t.nalEncrypted = true

		// pattern[48] was emitted with the probe and is already the first byte
		// of the following 144-byte clear region
		t.skip = avcPatternSkipSize - 1
	}

	for len(data) > 0 {
		// Clear regions can be written as whole slices
		if t.skip > 0 {
			n := min(len(data), t.skip)
			if err := t.write(data[:n], true); err != nil {
				return err
			}
			t.skip -= n
			data = data[n:]
			continue
		}

		// A full candidate block is encrypted only when another byte is known
		// to follow it. If the NAL ends here, finishNAL writes the complete block
		// clear, as required for the final Sample-AES island
		if t.patternLen == avcBlockSize {
			if err := t.block.CryptBlocks(t.pattern[:avcBlockSize]); err != nil {
				return err
			}
			if err := t.write(t.pattern[:avcBlockSize], true); err != nil {
				return err
			}
			t.patternLen = 0
			t.skip = avcPatternSkipSize
			continue
		}

		// Retain at most one partial AES block between payload calls
		n := copy(t.pattern[t.patternLen:avcBlockSize], data)
		t.patternLen += n
		data = data[n:]
	}
	return nil
}

func (t *Transformer) writeNALZeros(n int) error {
	for n > 0 {
		size := min(n, len(zeroBytes))
		if err := t.writeNAL(zeroBytes[:size]); err != nil {
			return err
		}
		n -= size
	}
	return nil
}

func (t *Transformer) beginNAL() {
	t.nalState = avcNALStateHeader
	t.nalEncrypted = false
	t.patternLen = 0
	t.skip = 0
	t.escaper.Reset()
}

func (t *Transformer) finishNAL() error {
	if t.nalState == avcNALStateHeader {
		return fmt.Errorf("AVC transformer: Annex-B start code without NAL header")
	}
	if t.nalState == avcNALStateProtected {
		if err := t.write(t.pattern[:t.patternLen], t.nalEncrypted); err != nil {
			return err
		}
		t.patternLen = 0
	}
	t.nalState = avcNALStateNone
	return nil
}

func (t *Transformer) writeZeros(n int, escaped bool) error {
	for n > 0 {
		size := min(n, len(zeroBytes))
		if err := t.write(zeroBytes[:size], escaped); err != nil {
			return err
		}
		n -= size
	}
	return nil
}

func (t *Transformer) write(data []byte, escaped bool) error {
	for len(data) > 0 {
		if len(t.pes) == 0 || t.pes[0].bytes == 0 {
			return fmt.Errorf("AVC transformer: missing PES for NAL payload")
		}
		pes := &t.pes[0]
		if !pes.started {
			if err := t.next.PESHeader(pes.header); err != nil {
				return err
			}
			pes.started = true
		}

		// Never consume bytes owned by the following PES in this iteration
		n := min(len(data), pes.bytes)
		output := data[:n]
		if escaped {
			t.scratch = t.escaper.Append(t.scratch[:0], output)
			output = t.scratch
		}
		if err := t.next.PESPayload(output); err != nil {
			return err
		}
		pes.bytes -= n
		data = data[n:]

		// This may close the current PES and expose the next queued one before
		// the remaining data is written
		if err := t.finishPES(); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transformer) finishPES() error {
	// A PES can close only after PESEnd was received and every source byte
	// assigned to it has left zeroRun/pattern and reached the downstream writer.
	// Consecutive empty pending PES records are drained in the same pass
	for len(t.pes) > 0 && t.pes[0].ended && t.pes[0].bytes == 0 {
		if !t.pes[0].started {
			if err := t.next.PESHeader(t.pes[0].header); err != nil {
				return err
			}
		}
		if err := t.next.PESEnd(); err != nil {
			return err
		}
		t.pes = t.pes[1:]
	}
	return nil
}
