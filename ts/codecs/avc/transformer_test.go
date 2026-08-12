package avc

import (
	"bytes"
	"errors"
	"testing"
)

type pesHandlerEvents struct {
	header   []byte
	payload  []byte
	payloads [][]byte
	ended    bool
	ends     int
}

type discardPESHandler struct{}

func (*discardPESHandler) PESHeader([]byte) error {
	return nil
}

func (*discardPESHandler) PESPayload([]byte) error {
	return nil
}

func (*discardPESHandler) PESEnd() error {
	return nil
}

func (e *pesHandlerEvents) PESHeader(header []byte) error {
	e.header = append([]byte(nil), header...)
	e.payloads = append(e.payloads, nil)
	return nil
}

func (e *pesHandlerEvents) PESPayload(payload []byte) error {
	e.payload = append(e.payload, payload...)
	i := len(e.payloads) - 1
	e.payloads[i] = append(e.payloads[i], payload...)
	return nil
}

func (e *pesHandlerEvents) PESEnd() error {
	e.ended = true
	e.ends++
	return nil
}

type recordingBlockCryptor struct {
	resets   int
	blocks   [][]byte
	resetErr error
	cryptErr error
	mutate   func([]byte)
}

func testVideoPESHeader() []byte {
	return []byte{
		0x00, 0x00, 0x01, 0xE0,
		0x00, 0x40,
		0x80, 0x00, 0x00,
	}
}

func (c *recordingBlockCryptor) Reset() error {
	c.resets++
	return c.resetErr
}

func (c *recordingBlockCryptor) CryptBlocks(data []byte) error {
	c.blocks = append(c.blocks, append([]byte(nil), data...))
	if c.mutate != nil {
		c.mutate(data)
	}
	return c.cryptErr
}

func TestTransformerStreamsAnnexBAcrossChunks(t *testing.T) {
	input := []byte{
		0x00, 0x00, 0x00, 0x01,
		0x67, 0x11, 0x22,
		0x00, 0x00, 0x01,
		0x61, 0x33, 0x44,
	}
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, nil)
	header := testVideoPESHeader()

	if err := transformer.PESHeader(header); err != nil {
		t.Fatal(err)
	}
	for _, b := range input {
		if err := transformer.PESPayload([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	wantHeader := append([]byte(nil), header...)
	wantHeader[4], wantHeader[5] = 0, 0
	if !bytes.Equal(next.header, wantHeader) {
		t.Fatalf("header = %x, want %x", next.header, wantHeader)
	}
	if !bytes.Equal(next.payload, input) {
		t.Fatalf("payload = %x, want %x", next.payload, input)
	}
	if !next.ended {
		t.Fatal("PES end was not forwarded")
	}
}

func TestTransformerContinuesProtectedNALAcrossPES(t *testing.T) {
	nalu := bytes.Repeat([]byte{0x55}, 49)
	nalu[0] = 0x65
	input := append([]byte{0x00, 0x00, 0x01}, nalu...)
	const firstPESNALBytes = 20
	split := 3 + firstPESNALBytes

	block := &recordingBlockCryptor{}
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, block)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input[:split]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if next.ends != 0 {
		t.Fatalf("PES ends = %d, want 0 before buffered bytes resolve", next.ends)
	}
	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input[split:]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(next.payload, input) {
		t.Fatalf("payload = %x, want %x", next.payload, input)
	}
	if len(next.payloads) != 2 {
		t.Fatalf("PES payloads = %d, want 2", len(next.payloads))
	}
	if !bytes.Equal(next.payloads[0], input[:split]) {
		t.Fatalf("first PES payload = %x, want %x", next.payloads[0], input[:split])
	}
	if !bytes.Equal(next.payloads[1], input[split:]) {
		t.Fatalf("second PES payload = %x, want %x", next.payloads[1], input[split:])
	}
	if next.ends != 2 {
		t.Fatalf("PES ends = %d, want 2", next.ends)
	}
	if block.resets != 1 {
		t.Fatalf("resets = %d, want 1", block.resets)
	}
	if len(block.blocks) != 1 {
		t.Fatalf("encrypted blocks = %d, want 1", len(block.blocks))
	}
	if !bytes.Equal(block.blocks[0], nalu[32:48]) {
		t.Fatalf("encrypted block = %x, want %x", block.blocks[0], nalu[32:48])
	}
}

func TestTransformerCountsOriginalEPBInProtectionPattern(t *testing.T) {
	nalu := bytes.Repeat([]byte{0x55}, 49)
	nalu[0] = 0x65
	nalu[30], nalu[31], nalu[32], nalu[33] = 0x00, 0x00, 0x03, 0x01
	block := &recordingBlockCryptor{}
	transformer := newTransformer(&pesHandlerEvents{}, block)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(append([]byte{0x00, 0x00, 0x01}, nalu...)); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if len(block.blocks) != 1 {
		t.Fatalf("encrypted blocks = %d, want 1", len(block.blocks))
	}
	if !bytes.Equal(block.blocks[0], nalu[32:48]) {
		t.Fatalf("encrypted block = %x, want %x", block.blocks[0], nalu[32:48])
	}
}

func TestTransformerReappliesEmulationPreventionToProtectedNAL(t *testing.T) {
	nalu := bytes.Repeat([]byte{0x55}, 49)
	nalu[0] = 0x65
	nalu[30], nalu[31], nalu[32], nalu[33] = 0x00, 0x00, 0x03, 0x01
	input := append([]byte{0x00, 0x00, 0x01}, nalu...)
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, &recordingBlockCryptor{})

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	want := append([]byte(nil), input[:3+32]...)
	want = append(want, 0x03)
	want = append(want, input[3+32:]...)
	if !bytes.Equal(next.payload, want) {
		t.Fatalf("payload = %x, want %x", next.payload, want)
	}
}

func TestTransformerDoesNotReapplyEmulationPreventionToShortNAL(t *testing.T) {
	nalu := bytes.Repeat([]byte{0x55}, 48)
	nalu[0] = 0x65
	nalu[30], nalu[31], nalu[32], nalu[33] = 0x00, 0x00, 0x03, 0x01
	input := append([]byte{0x00, 0x00, 0x01}, nalu...)
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, &recordingBlockCryptor{})

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(next.payload, input) {
		t.Fatalf("payload = %x, want %x", next.payload, input)
	}
}

func TestTransformerContinuesStartCodeAcrossPES(t *testing.T) {
	first := []byte{0x00, 0x00, 0x01, 0x67, 0x11, 0x00, 0x00}
	second := []byte{0x01, 0x61, 0x22}
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, nil)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(first); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(second); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if len(next.payloads) != 2 {
		t.Fatalf("PES payloads = %d, want 2", len(next.payloads))
	}
	if !bytes.Equal(next.payloads[0], first) {
		t.Fatalf("first PES payload = %x, want %x", next.payloads[0], first)
	}
	if !bytes.Equal(next.payloads[1], second) {
		t.Fatalf("second PES payload = %x, want %x", next.payloads[1], second)
	}
}

func TestTransformerStartsAnnexBAcrossPES(t *testing.T) {
	first := []byte{0x00, 0x00}
	second := []byte{0x01, 0x67, 0x11}
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, nil)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(first); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(second); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if len(next.payloads) != 2 {
		t.Fatalf("PES payloads = %d, want 2", len(next.payloads))
	}
	if !bytes.Equal(next.payloads[0], first) {
		t.Fatalf("first PES payload = %x, want %x", next.payloads[0], first)
	}
	if !bytes.Equal(next.payloads[1], second) {
		t.Fatalf("second PES payload = %x, want %x", next.payloads[1], second)
	}
}

func TestTransformerContinuesCryptBlockAcrossPES(t *testing.T) {
	nalu := make([]byte, 208)
	nalu[0] = 0x65
	for i := 1; i < len(nalu); i++ {
		nalu[i] = byte(i%250 + 4)
	}
	input := append([]byte{0x00, 0x00, 0x01}, nalu...)
	split := 3 + 200
	block := &recordingBlockCryptor{}
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, block)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input[:split]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input[split:]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if len(next.payloads) != 2 {
		t.Fatalf("PES payloads = %d, want 2", len(next.payloads))
	}
	if !bytes.Equal(next.payloads[0], input[:split]) {
		t.Fatalf("first PES payload = %x, want %x", next.payloads[0], input[:split])
	}
	if !bytes.Equal(next.payloads[1], input[split:]) {
		t.Fatalf("second PES payload = %x, want %x", next.payloads[1], input[split:])
	}
	if len(block.blocks) != 1 {
		t.Fatalf("encrypted blocks = %d, want 1", len(block.blocks))
	}
}

func TestTransformerLeavesFinalCompleteCryptIslandClear(t *testing.T) {
	nalu := make([]byte, 208)
	nalu[0] = 0x65
	for i := 1; i < len(nalu); i++ {
		nalu[i] = byte(i%250 + 4)
	}
	input := append([]byte{0x00, 0x00, 0x00, 0x01}, nalu...)
	block := &recordingBlockCryptor{}
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, block)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	for start := 0; start < len(input); {
		end := min(start+13, len(input))
		if err := transformer.PESPayload(input[start:end]); err != nil {
			t.Fatal(err)
		}
		start = end
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if block.resets != 1 {
		t.Fatalf("resets = %d, want 1", block.resets)
	}
	if len(block.blocks) != 1 {
		t.Fatalf("encrypted blocks = %d, want 1", len(block.blocks))
	}
	if !bytes.Equal(block.blocks[0], nalu[32:48]) {
		t.Fatalf("first block = %x, want %x", block.blocks[0], nalu[32:48])
	}
	if !bytes.Equal(next.payload, input) {
		t.Fatal("no-op block cryptor changed payload")
	}
}

func TestTransformerEncryptsCompleteIslandWithTrailingByte(t *testing.T) {
	nalu := make([]byte, 209)
	nalu[0] = 0x65
	for i := 1; i < len(nalu); i++ {
		nalu[i] = byte(i%250 + 4)
	}
	input := append([]byte{0x00, 0x00, 0x01}, nalu...)
	block := &recordingBlockCryptor{}
	transformer := newTransformer(&pesHandlerEvents{}, block)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.Flush(); err != nil {
		t.Fatal(err)
	}

	if len(block.blocks) != 2 {
		t.Fatalf("encrypted blocks = %d, want 2", len(block.blocks))
	}
	if !bytes.Equal(block.blocks[1], nalu[192:208]) {
		t.Fatalf("second block = %x, want %x", block.blocks[1], nalu[192:208])
	}
}

func TestTransformerProtectsOnlyLongTypeOneAndFiveNALUs(t *testing.T) {
	tests := []struct {
		name      string
		nalType   byte
		size      int
		wantCalls int
	}{
		{"type one", 1, 49, 1},
		{"type five", 5, 49, 1},
		{"type two", 2, 49, 0},
		{"short type five", 5, 48, 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nalu := bytes.Repeat([]byte{0x55}, test.size)
			nalu[0] = 0x60 | test.nalType
			input := append([]byte{0x00, 0x00, 0x01}, nalu...)
			block := &recordingBlockCryptor{}
			next := &pesHandlerEvents{}
			transformer := newTransformer(next, block)

			if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
				t.Fatal(err)
			}
			if err := transformer.PESPayload(input); err != nil {
				t.Fatal(err)
			}
			if err := transformer.PESEnd(); err != nil {
				t.Fatal(err)
			}
			if err := transformer.Flush(); err != nil {
				t.Fatal(err)
			}

			if got := len(block.blocks); got != test.wantCalls {
				t.Fatalf("encrypted blocks = %d, want %d", got, test.wantCalls)
			}
			if !bytes.Equal(next.payload, input) {
				t.Fatal("no-op block cryptor changed payload")
			}
		})
	}
}

func TestTransformerEscapesCryptedBytes(t *testing.T) {
	nalu := bytes.Repeat([]byte{0x55}, 49)
	nalu[0] = 0x65
	input := append([]byte{0x00, 0x00, 0x01}, nalu...)
	block := &recordingBlockCryptor{mutate: func(data []byte) {
		for i := range data {
			data[i] = 0x44
		}
		data[0], data[1], data[2] = 0x00, 0x00, 0x01
	}}
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, block)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}

	want := append([]byte{}, input[:3+32]...)
	want = append(want, 0x00, 0x00, 0x03, 0x01)
	want = append(want, bytes.Repeat([]byte{0x44}, 13)...)
	want = append(want, nalu[48])
	if !bytes.Equal(next.payload, want) {
		t.Fatalf("payload = %x, want %x", next.payload, want)
	}
}

func TestTransformerEscapesAcrossPESBoundary(t *testing.T) {
	nalu := bytes.Repeat([]byte{0x55}, 49)
	nalu[0] = 0x65
	input := append([]byte{0x00, 0x00, 0x01}, nalu...)
	split := 3 + 34
	block := &recordingBlockCryptor{mutate: func(data []byte) {
		for i := range data {
			data[i] = 0x44
		}
		data[0], data[1], data[2] = 0x00, 0x00, 0x01
	}}
	next := &pesHandlerEvents{}
	transformer := newTransformer(next, block)

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input[:split]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESPayload(input[split:]); err != nil {
		t.Fatal(err)
	}
	if err := transformer.PESEnd(); err != nil {
		t.Fatal(err)
	}

	first := append([]byte{}, input[:3+32]...)
	first = append(first, 0x00, 0x00)
	second := append([]byte{0x03, 0x01}, bytes.Repeat([]byte{0x44}, 13)...)
	second = append(second, nalu[48])
	if !bytes.Equal(next.payloads[0], first) {
		t.Fatalf("first PES payload = %x, want %x", next.payloads[0], first)
	}
	if !bytes.Equal(next.payloads[1], second) {
		t.Fatalf("second PES payload = %x, want %x", next.payloads[1], second)
	}
}

func TestTransformerPropagatesBlockCryptorError(t *testing.T) {
	wantErr := errors.New("crypt failed")
	block := &recordingBlockCryptor{cryptErr: wantErr}
	transformer := newTransformer(&pesHandlerEvents{}, block)
	nalu := bytes.Repeat([]byte{0x55}, 49)
	nalu[0] = 0x65

	if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
		t.Fatal(err)
	}
	err := transformer.PESPayload(append([]byte{0x00, 0x00, 0x01}, nalu...))
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

func BenchmarkTransformer(b *testing.B) {
	payload := bytes.Repeat([]byte{0x55}, 1024*1024)
	payload[0] = 0x65
	payload = append([]byte{0x00, 0x00, 0x01}, payload...)
	header := testVideoPESHeader()
	b.SetBytes(int64(len(payload)))

	for b.Loop() {
		transformer := newTransformer(&discardPESHandler{}, &fuzzBlockCryptor{})
		if err := transformer.PESHeader(header); err != nil {
			b.Fatal(err)
		}
		if err := transformer.PESPayload(payload); err != nil {
			b.Fatal(err)
		}
		if err := transformer.PESEnd(); err != nil {
			b.Fatal(err)
		}
		if err := transformer.Flush(); err != nil {
			b.Fatal(err)
		}
	}
}
