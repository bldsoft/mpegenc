package ac3

import (
	"bytes"
	"testing"

	"github.com/bldsoft/mpegenc/internal/go-astits"
	"github.com/bldsoft/mpegenc/ts/internal/pmtsignal"
)

type pesHandler struct {
	payloads [][]byte
	ends     int
}

func (h *pesHandler) PESHeader([]byte) error {
	h.payloads = append(h.payloads, nil)
	return nil
}

func (h *pesHandler) PESPayload(payload []byte) error {
	i := len(h.payloads) - 1
	h.payloads[i] = append(h.payloads[i], payload...)
	return nil
}

func (h *pesHandler) PESEnd() error {
	h.ends++
	return nil
}

type blockCryptor struct {
	resets int
	blocks [][]byte
	mutate bool
}

func (c *blockCryptor) Reset() error {
	c.resets++
	return nil
}

func (c *blockCryptor) CryptBlocks(data []byte) error {
	c.blocks = append(c.blocks, append([]byte(nil), data...))
	if c.mutate {
		for i := range data {
			data[i] ^= 0xFF
		}
	}
	return nil
}

func ac3Frame(frmsizecod byte) []byte {
	size := int(frameSizeWords[frmsizecod][0]) * 2
	frame := make([]byte, size)
	for i := 2; i < len(frame); i++ {
		frame[i] = byte(i)
	}
	frame[0] = 0x0B
	frame[1] = 0x77
	frame[4] = frmsizecod
	frame[5] = 8 << 3
	return frame
}

func pesHeader() []byte {
	return []byte{0x00, 0x00, 0x01, 0xBD, 0x00, 0x00, 0x80, 0x00, 0x00}
}

func discardPMTPatch(pmtsignal.Patch) error {
	return nil
}

func TestTransformerEncryptsCompleteBlocksPerFrame(t *testing.T) {
	first := ac3Frame(0)
	second := ac3Frame(4)
	input := append(append([]byte(nil), first...), second...)
	next := &pesHandler{}
	block := &blockCryptor{mutate: true}
	signals := 0
	transformer := NewTransformer(next, block, func(pmtsignal.Patch) error {
		signals++
		return nil
	})

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	for start := 0; start < len(input); start += 11 {
		end := min(start+11, len(input))
		if err := transformer.PESPayload(input[start:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if block.resets != 2 {
		t.Fatalf("resets = %d, want 2", block.resets)
	}
	if len(block.blocks) != 2 || len(block.blocks[0]) != 112 || len(block.blocks[1]) != 176 {
		t.Fatalf("encrypted block lengths = %d, %d", len(block.blocks[0]), len(block.blocks[1]))
	}
	output := next.payloads[0]
	if !bytes.Equal(output[:16], input[:16]) {
		t.Fatal("first frame clear bytes changed")
	}
	if bytes.Equal(output[16:128], input[16:128]) {
		t.Fatal("first frame protected bytes unchanged")
	}
	if signals != 1 {
		t.Fatalf("PMT signals = %d, want 1", signals)
	}
}

func TestTransformerPublishesConfigFromHeader(t *testing.T) {
	frame := ac3Frame(0)
	var patch pmtsignal.Patch
	transformer := NewTransformer(&pesHandler{}, &blockCryptor{}, func(got pmtsignal.Patch) error {
		patch = got
		return nil
	})

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[:ac3SetupSize]); err != nil {
		t.Fatal(err)
	}

	if patch == nil {
		t.Fatal("PMT patch was not signaled")
	}
	stream := &astits.PMTElementaryStream{}
	patch(stream)
	if stream.StreamType != 0xC1 {
		t.Fatalf("stream type = 0x%02X", stream.StreamType)
	}
	if stream.ElementaryStreamDescriptors[0].PrivateDataIndicator.Indicator != 0x61633364 {
		t.Fatal("missing ac3d descriptor")
	}
	registration := stream.ElementaryStreamDescriptors[1].Registration
	want := append([]byte{'z', 'a', 'c', '3', 0, 0, 1, 10}, frame[:10]...)
	if registration == nil || registration.FormatIdentifier != 0x61706164 ||
		!bytes.Equal(registration.AdditionalIdentificationInfo, want) {
		t.Fatalf("AC-3 setup = %x", registration.AdditionalIdentificationInfo)
	}
}

func TestTransformerPreservesPESBoundariesAcrossFrame(t *testing.T) {
	frame := ac3Frame(0)
	next := &pesHandler{}
	transformer := NewTransformer(next, &blockCryptor{}, discardPMTPatch)

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[:40]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[40:]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if len(next.payloads) != 2 || next.ends != 2 {
		t.Fatalf("PES payloads = %d, ends = %d", len(next.payloads), next.ends)
	}
	if !bytes.Equal(next.payloads[0], frame[:40]) || !bytes.Equal(next.payloads[1], frame[40:]) {
		t.Fatal("PES payload boundaries changed")
	}
}

func TestTransformerRejectsTruncatedFrame(t *testing.T) {
	transformer := NewTransformer(
		&pesHandler{},
		&blockCryptor{},
		discardPMTPatch,
	)
	frame := ac3Frame(0)

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[:40]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err == nil {
		t.Fatal("expected truncated frame error")
	}
}
