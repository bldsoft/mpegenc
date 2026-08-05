package packets

import (
	"bytes"
	"strings"
	"testing"
)

type pesEvents struct {
	headers  [][]byte
	payloads [][]byte
	ends     int
}

func (e *pesEvents) PESHeader(header []byte) error {
	e.headers = append(e.headers, append([]byte(nil), header...))
	return nil
}

func (e *pesEvents) PESPayload(payload []byte) error {
	e.payloads = append(e.payloads, append([]byte(nil), payload...))
	return nil
}

func (e *pesEvents) PESEnd() error {
	e.ends++
	return nil
}

func pes(payloadLength uint16, headerData []byte, payload []byte) []byte {
	header := []byte{0, 0, 1, 0xE0, byte(payloadLength >> 8), byte(payloadLength), 0x80, 0x80, byte(len(headerData))}
	return append(append(header, headerData...), payload...)
}

func TestPESCollectorHeaderAndPayloadSplitAcrossChunks(t *testing.T) {
	data := pes(13, []byte{0x21, 0, 1, 0, 1}, []byte{1, 2, 3, 4, 5})
	var machine PESCollector
	var got pesEvents

	if err := machine.Consume(true, data[:4], &got); err != nil {
		t.Fatal(err)
	}
	if err := machine.Consume(false, data[4:11], &got); err != nil {
		t.Fatal(err)
	}
	if err := machine.Consume(false, data[11:], &got); err != nil {
		t.Fatal(err)
	}

	if len(got.headers) != 1 || !bytes.Equal(got.headers[0], data[:14]) {
		t.Fatalf("headers = %x, want %x", got.headers, data[:14])
	}
	if len(got.payloads) != 1 || !bytes.Equal(got.payloads[0], data[14:]) {
		t.Fatalf("payloads = %x, want %x", got.payloads, data[14:])
	}
	if got.ends != 1 {
		t.Fatalf("ends = %d, want 1", got.ends)
	}
}

func TestPESCollectorUnboundedPESFinishesAtNextPUSI(t *testing.T) {
	first := pes(0, nil, []byte{1, 2, 3})
	second := pes(6, nil, []byte{4, 5, 6})
	var machine PESCollector
	var got pesEvents

	if err := machine.Consume(true, first, &got); err != nil {
		t.Fatal(err)
	}
	if err := machine.Consume(true, second, &got); err != nil {
		t.Fatal(err)
	}

	if got.ends != 2 {
		t.Fatalf("ends = %d, want 2", got.ends)
	}
	if len(got.payloads) != 2 || !bytes.Equal(got.payloads[0], []byte{1, 2, 3}) || !bytes.Equal(got.payloads[1], []byte{4, 5, 6}) {
		t.Fatalf("payloads = %x", got.payloads)
	}
}

func TestPESCollectorFlush(t *testing.T) {
	var machine PESCollector
	var got pesEvents
	if err := machine.Consume(true, pes(0, nil, []byte{1, 2, 3}), &got); err != nil {
		t.Fatal(err)
	}
	if err := machine.Flush(&got); err != nil {
		t.Fatal(err)
	}
	if got.ends != 1 {
		t.Fatalf("ends = %d, want 1", got.ends)
	}
}

func TestPESCollectorRejectsMalformedPES(t *testing.T) {
	var machine PESCollector
	var got pesEvents
	if err := machine.Consume(true, []byte{0, 0, 2}, &got); err == nil || !strings.Contains(err.Error(), "start code") {
		t.Fatalf("error = %v, want start code error", err)
	}
}

func TestPESCollectorRejectsTruncatedBoundedPES(t *testing.T) {
	var machine PESCollector
	var got pesEvents
	if err := machine.Consume(true, pes(6, nil, []byte{1, 2}), &got); err != nil {
		t.Fatal(err)
	}
	if err := machine.Flush(&got); err == nil || !strings.Contains(err.Error(), "truncated PES payload") {
		t.Fatalf("error = %v, want truncated payload error", err)
	}
}
