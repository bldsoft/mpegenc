package aac

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

func adtsFrame(size int, crc bool) []byte {
	headerSize := 7
	protectionAbsent := byte(1)
	if crc {
		headerSize = 9
		protectionAbsent = 0
	}
	frame := make([]byte, size)
	for i := headerSize; i < len(frame); i++ {
		frame[i] = byte(i)
	}
	frame[0] = 0xFF
	frame[1] = 0xF0 | protectionAbsent
	frame[2] = 0x50
	frame[3] = 0x80 | byte((size>>11)&0x03)
	frame[4] = byte(size >> 3)
	frame[5] = byte(size&0x07) << 5
	frame[6] = 0xFC
	return frame
}

func pesHeader() []byte {
	return []byte{0x00, 0x00, 0x01, 0xC0, 0x00, 0x00, 0x80, 0x00, 0x00}
}

func discardPMTPatch(pmtsignal.Patch) error {
	return nil
}

func TestTransformerEncryptsCompleteBlocksPerFrame(t *testing.T) {
	first := adtsFrame(64, false)
	second := adtsFrame(80, false)
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
	if len(block.blocks) != 2 || len(block.blocks[0]) != 32 || len(block.blocks[1]) != 48 {
		t.Fatalf("encrypted block lengths = %d, %d", len(block.blocks[0]), len(block.blocks[1]))
	}
	output := next.payloads[0]
	if !bytes.Equal(output[:23], input[:23]) || !bytes.Equal(output[55:64], input[55:64]) {
		t.Fatal("first frame clear bytes changed")
	}
	if bytes.Equal(output[23:55], input[23:55]) {
		t.Fatal("first frame protected bytes unchanged")
	}
	if signals != 1 {
		t.Fatalf("PMT signals = %d, want 1", signals)
	}
}

func TestTransformerPublishesConfigFromHeader(t *testing.T) {
	frame := adtsFrame(64, false)
	var patch pmtsignal.Patch
	transformer := NewTransformer(&pesHandler{}, &blockCryptor{}, func(got pmtsignal.Patch) error {
		patch = got
		return nil
	})

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[:adtsHeaderSize]); err != nil {
		t.Fatal(err)
	}

	if patch == nil {
		t.Fatal("PMT patch was not signaled")
	}
	stream := &astits.PMTElementaryStream{}
	patch(stream)
	registration := stream.ElementaryStreamDescriptors[1].Registration
	if !bytes.Equal(registration.AdditionalIdentificationInfo, []byte{
		'z', 'a', 'a', 'c', 0, 0, 1, 2, 0x12, 0x10,
	}) {
		t.Fatalf("AAC setup = %x", registration.AdditionalIdentificationInfo)
	}
}

func TestTransformerPreservesPESBoundariesAcrossFrame(t *testing.T) {
	frame := adtsFrame(64, true)
	next := &pesHandler{}
	transformer := NewTransformer(next, &blockCryptor{}, discardPMTPatch)

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[:30]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[30:]); err != nil {
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
	if !bytes.Equal(next.payloads[0], frame[:30]) || !bytes.Equal(next.payloads[1], frame[30:]) {
		t.Fatal("PES payload boundaries changed")
	}
}

func TestTransformerRejectsTruncatedFrame(t *testing.T) {
	transformer := NewTransformer(
		&pesHandler{},
		&blockCryptor{},
		discardPMTPatch,
	)
	frame := adtsFrame(64, false)

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
