package avc

import (
	"fmt"

	"github.com/bldsoft/mpegenc/sampleaes"
	"github.com/bldsoft/mpegenc/ts/internal/pmtsignal"
	"github.com/bldsoft/mpegenc/ts/packets"
)

// Transformer processes an Annex-B AVC elementary stream carried by PES
// payload events. It recognizes start codes across payload chunks, classifies
// NAL units, and applies Sample-AES only to slice NAL types 1 and 5.
type Transformer struct {
	next  packets.PESHandler
	crypt bool

	inputPESOpen           bool // E.g. received PESHeader() but not PESEnd() yet
	outputPESOpen          bool // E.g. sent PESHeader() but not PESEnd() yet
	pendingHeaders         [][]byte
	nalState               avcNALState
	zeroRun                int   // Number of consecutive zero bytes (for start code recognition)
	pesEndOffsetsInZeroRun []int // E.g. []int{2,5} means that PES A ends after zero #2 and PES B ends after zero #5

	pattern avcSampleAESPattern
	escaper ebspEscaper
	output  []byte
}

// avcNALState records how bytes after the latest Annex-B start code must be
// interpreted until the next start code.
type avcNALState uint8

const (
	avcNALStateNone        avcNALState = iota // Didnt find start code yet
	avcNALStateHeader                         // Waiting for NAL header
	avcNALStatePassthrough                    // Not sample-AES protected, pass through as is
	avcNALStateProtected                      // Needs Sample-AES
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
		next:    next,
		crypt:   block != nil,
		pattern: newAVCSampleAESPattern(block),
	}
}

func (t *Transformer) PESHeader(header []byte) error {
	if t.inputPESOpen {
		return fmt.Errorf("AVC transformer: previous PES is still open")
	}
	if len(header) < 6 {
		return fmt.Errorf("AVC transformer: PES header is too short: %d", len(header))
	}
	outputHeader := append([]byte(nil), header...)

	// We dont know what will happen to the PES's length after we round trip emulation prevention and encrypt.
	// Thus we use 00 00 to indicate that the PES's length is unknown. This is a valid value
	// TODO This causes problems with ffplay for example. The output is valid but due to 0 peslen ffmpeg does not
	// remove 03 emulation prevention on the last 1-2 peses in the chunk and outputs some warnings.
	// Should we buffer the whole pes to be able to specify its length?
	outputHeader[4] = 0
	outputHeader[5] = 0
	if t.outputPESOpen {
		t.pendingHeaders = append(t.pendingHeaders, outputHeader)
	} else {
		if err := t.next.PESHeader(outputHeader); err != nil {
			return err
		}
		t.outputPESOpen = true
	}
	t.inputPESOpen = true
	return nil
}

// raw AVC bytes
func (t *Transformer) PESPayload(payload []byte) error {
	if !t.inputPESOpen {
		return fmt.Errorf("AVC transformer: payload outside PES")
	}
	for _, b := range payload {
		if err := t.consumeByte(b); err != nil {
			return err
		}
	}
	return t.flushOutput()
}

func (t *Transformer) PESEnd() error {
	if !t.inputPESOpen {
		return fmt.Errorf("AVC transformer: no open PES")
	}
	if t.zeroRun > 0 {
		t.pesEndOffsetsInZeroRun = append(t.pesEndOffsetsInZeroRun, t.zeroRun)
	} else {
		if err := t.writeNALBoundary(); err != nil {
			return err
		}
	}
	t.inputPESOpen = false
	return nil
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
	if err := t.drainZeroRun(
		func(b byte) error {
			t.output = append(t.output, b)
			return nil
		},
		t.emitPESBoundary,
	); err != nil {
		return err
	}
	return t.flushOutput()
}

func (t *Transformer) consumeByte(b byte) error {
	if b == 0 {
		t.zeroRun++
		return nil
	}

	// Found Annex-B start code
	if b == 1 && t.zeroRun >= 2 {
		if t.nalState != avcNALStateNone {
			if err := t.finishNAL(); err != nil {
				return err
			}
		}
		if err := t.drainZeroRun(
			func(b byte) error {
				t.output = append(t.output, b)
				return nil
			},
			t.emitPESBoundary,
		); err != nil {
			return err
		}
		t.output = append(t.output, 1)
		t.beginNAL()
		return nil
	}
	if t.nalState == avcNALStateNone {
		return fmt.Errorf("AVC transformer: bytes before Annex-B start code")
	}
	if err := t.drainZeroRun(t.writeNALByte, t.writeNALBoundary); err != nil {
		return err
	}
	return t.writeNALByte(b)
}

func (t *Transformer) drainZeroRun(
	writeByte func(byte) error,
	writeBoundary func() error,
) error {
	zeroOffset := 0
	for _, pesEndOffset := range t.pesEndOffsetsInZeroRun {
		for zeroOffset < pesEndOffset {
			if err := writeByte(0); err != nil {
				return err
			}
			zeroOffset++
		}
		if err := writeBoundary(); err != nil {
			return err
		}
	}

	for zeroOffset < t.zeroRun {
		if err := writeByte(0); err != nil {
			return err
		}
		zeroOffset++
	}

	t.zeroRun = 0
	t.pesEndOffsetsInZeroRun = t.pesEndOffsetsInZeroRun[:0]
	return nil
}

func (t *Transformer) beginNAL() {
	t.nalState = avcNALStateHeader
	t.pattern.Reset()
	t.escaper.Reset()
}

func (t *Transformer) writeNALByte(b byte) error {
	if t.nalState == avcNALStateHeader {
		nalType := b & 0x1F
		if t.crypt && (nalType == 1 || nalType == 5) {
			t.nalState = avcNALStateProtected
		} else {
			t.nalState = avcNALStatePassthrough
		}
	}
	if t.nalState == avcNALStatePassthrough {
		t.output = append(t.output, b)
		return nil
	}
	return t.pattern.WriteByte(b, t.emitEscapedByte, t.emitPESBoundary)
}

func (t *Transformer) writeNALBoundary() error {
	if t.nalState != avcNALStateProtected {
		return t.emitPESBoundary()
	}
	return t.pattern.Boundary(t.emitPESBoundary)
}

func (t *Transformer) finishNAL() error {
	if t.nalState == avcNALStateHeader {
		return fmt.Errorf("AVC transformer: Annex-B start code without NAL header")
	}
	if t.nalState == avcNALStateProtected {
		emit := t.emitEscapedByte
		if !t.pattern.protected {
			emit = func(b byte) {
				t.output = append(t.output, b)
			}
		}
		if err := t.pattern.Finish(emit, t.emitPESBoundary); err != nil {
			return err
		}
	}
	t.nalState = avcNALStateNone
	return nil
}

func (t *Transformer) emitEscapedByte(b byte) {
	t.output = t.escaper.AppendByte(t.output, b)
}

func (t *Transformer) flushOutput() error {
	if len(t.output) == 0 {
		return nil
	}
	if err := t.next.PESPayload(t.output); err != nil {
		return err
	}
	t.output = t.output[:0]
	return nil
}

func (t *Transformer) emitPESBoundary() error {
	if err := t.flushOutput(); err != nil {
		return err
	}
	if err := t.next.PESEnd(); err != nil {
		return err
	}
	t.outputPESOpen = false
	if len(t.pendingHeaders) == 0 {
		return nil
	}
	if err := t.next.PESHeader(t.pendingHeaders[0]); err != nil {
		return err
	}
	t.pendingHeaders = t.pendingHeaders[1:]
	t.outputPESOpen = true
	return nil
}
