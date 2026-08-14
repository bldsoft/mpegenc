package eac3

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

func eac3Frame(size int, numBlocksCode byte) []byte {
	frameSizeCode := size/2 - 1
	frame := make([]byte, size)
	for i := 2; i < len(frame); i++ {
		frame[i] = byte(i)
	}
	frame[0] = 0x0B
	frame[1] = 0x77
	frame[2] = byte(frameSizeCode >> 8)
	frame[3] = byte(frameSizeCode)
	frame[4] = numBlocksCode<<4 | 2<<1
	frame[5] = 16 << 3
	return frame
}

func pesHeader() []byte {
	return []byte{0x00, 0x00, 0x01, 0xBD, 0x00, 0x00, 0x80, 0x00, 0x00}
}

func discardPMTPatch(pmtsignal.Patch) error {
	return nil
}

func TestTransformerResetsCBCForIndependentSyncframes(t *testing.T) {
	frame := eac3Frame(64, 0)
	input := bytes.Repeat(frame, 7)
	next := &pesHandler{}
	block := &blockCryptor{mutate: true}
	transformer := NewTransformer(next, block, discardPMTPatch)

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

	if block.resets != 7 {
		t.Fatalf("resets = %d, want 7", block.resets)
	}
	if len(block.blocks) != 7 {
		t.Fatalf("encrypted syncframes = %d, want 7", len(block.blocks))
	}
	for i := range 7 {
		start := i * len(frame)
		if !bytes.Equal(next.payloads[0][start:start+16], input[start:start+16]) {
			t.Fatalf("syncframe %d clear bytes changed", i)
		}
		if bytes.Equal(next.payloads[0][start+16:start+len(frame)], input[start+16:start+len(frame)]) {
			t.Fatalf("syncframe %d protected bytes unchanged", i)
		}
	}
}

func TestTransformerRetainsBufferForNextSyncframe(t *testing.T) {
	frame := eac3Frame(4096, 0)
	transformer := NewTransformer(&pesHandler{}, &blockCryptor{}, discardPMTPatch)

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame); err != nil {
		t.Fatal(err)
	}

	if len(transformer.buffer) != 0 {
		t.Fatalf("buffer length = %d, want 0", len(transformer.buffer))
	}
	if cap(transformer.buffer) < len(frame) {
		t.Fatalf("buffer capacity = %d, want at least %d", cap(transformer.buffer), len(frame))
	}
}

func TestParseSyncframeHeaderFrameSize(t *testing.T) {
	header, err := parseSyncframeHeader([]byte{0x0B, 0x77, 0x07, 0xFF, 0x04, 0x87, 0xC4})
	if err != nil {
		t.Fatal(err)
	}
	if header.frameSize != 4096 {
		t.Fatalf("frame size = %d, want 4096", header.frameSize)
	}
}

func TestTransformerPublishesEnhancedAC3Setup(t *testing.T) {
	frame := eac3Frame(64, 0)
	var patch pmtsignal.Patch
	transformer := NewTransformer(&pesHandler{}, &blockCryptor{}, func(got pmtsignal.Patch) error {
		patch = got
		return nil
	})

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[:7]); err != nil {
		t.Fatal(err)
	}

	if patch == nil {
		t.Fatal("PMT patch was not signaled")
	}
	stream := &astits.PMTElementaryStream{}
	patch(stream)
	if stream.StreamType != 0xC2 {
		t.Fatalf("stream type = 0x%02X", stream.StreamType)
	}
	if stream.ElementaryStreamDescriptors[0].PrivateDataIndicator.Indicator != 0x65633364 {
		t.Fatal("missing ec3d descriptor")
	}
	registration := stream.ElementaryStreamDescriptors[1].Registration
	want := []byte{'z', 'e', 'c', '3', 0, 0, 1, 5, 0x03, 0x00, 0x20, 0x04, 0x00}
	if registration == nil || registration.FormatIdentifier != 0x61706164 ||
		!bytes.Equal(registration.AdditionalIdentificationInfo, want) {
		t.Fatalf("E-AC-3 setup = %x", registration.AdditionalIdentificationInfo)
	}
}

func TestTransformerPreservesPESBoundariesAcrossSyncframe(t *testing.T) {
	frame := eac3Frame(64, 3)
	next := &pesHandler{}
	transformer := NewTransformer(next, &blockCryptor{}, discardPMTPatch)

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[:20]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[20:]); err != nil {
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
	if !bytes.Equal(next.payloads[0], frame[:20]) || !bytes.Equal(next.payloads[1], frame[20:]) {
		t.Fatal("PES payload boundaries changed")
	}
}

func TestTransformerRejectsTruncatedSyncframe(t *testing.T) {
	transformer := NewTransformer(&pesHandler{}, &blockCryptor{}, discardPMTPatch)
	frame := eac3Frame(64, 3)

	if err := transformer.PESHeader(pesHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(frame[:20]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err == nil {
		t.Fatal("expected truncated syncframe error")
	}
}
