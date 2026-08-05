package avc

import (
	"bytes"
	"testing"
)

func TestEBSPEscaperStreamsAcrossChunks(t *testing.T) {
	var escaper ebspEscaper
	var got []byte

	for _, chunk := range [][]byte{
		{0x00},
		{0x00},
		{0x01, 0x02, 0x00},
		{0x00, 0x03, 0x04},
	} {
		got = escaper.Append(got, chunk)
	}

	want := []byte{
		0x00, 0x00, 0x03, 0x01,
		0x02,
		0x00, 0x00, 0x03, 0x03,
		0x04,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("escaped bytes = %x, want %x", got, want)
	}
}

func TestEBSPEscaperResetNALState(t *testing.T) {
	var escaper ebspEscaper
	escaped := escaper.Append(nil, []byte{0x00, 0x00})
	escaper.Reset()
	escaped = escaper.Append(escaped, []byte{0x01})
	if want := []byte{0x00, 0x00, 0x01}; !bytes.Equal(escaped, want) {
		t.Fatalf("escaped bytes = %x, want %x", escaped, want)
	}
}
