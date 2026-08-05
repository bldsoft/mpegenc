package avc

import (
	"bytes"
	"testing"
)

func TestAVCSampleAESPatternLeavesFinalCompleteIslandClear(t *testing.T) {
	input := make([]byte, 208)
	for i := range input {
		input[i] = byte(i%250 + 4)
	}
	block := &recordingBlockCryptor{}
	pattern := newAVCSampleAESPattern(block)
	var output []byte

	for _, b := range input {
		if err := pattern.WriteByte(b, func(b byte) {
			output = append(output, b)
		}); err != nil {
			t.Fatal(err)
		}
	}
	pattern.Finish(func(b byte) {
		output = append(output, b)
	})

	if block.resets != 1 {
		t.Fatalf("resets = %d, want 1", block.resets)
	}
	if len(block.blocks) != 1 {
		t.Fatalf("encrypted blocks = %d, want 1", len(block.blocks))
	}
	if !bytes.Equal(block.blocks[0], input[32:48]) {
		t.Fatalf("first block = %x, want %x", block.blocks[0], input[32:48])
	}
	if !bytes.Equal(output, input) {
		t.Fatal("no-op block cryptor changed payload")
	}
}

func TestAVCSampleAESPatternEncryptsCompleteIslandWithTrailingByte(t *testing.T) {
	input := make([]byte, 209)
	for i := range input {
		input[i] = byte(i%250 + 4)
	}
	block := &recordingBlockCryptor{}
	pattern := newAVCSampleAESPattern(block)
	var output []byte

	for _, b := range input {
		if err := pattern.WriteByte(b, func(b byte) {
			output = append(output, b)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := pattern.Finish(func(b byte) {
		output = append(output, b)
	}); err != nil {
		t.Fatal(err)
	}

	if len(block.blocks) != 2 {
		t.Fatalf("encrypted blocks = %d, want 2", len(block.blocks))
	}
	if !bytes.Equal(block.blocks[1], input[192:208]) {
		t.Fatalf("second block = %x, want %x", block.blocks[1], input[192:208])
	}
	if !bytes.Equal(output, input) {
		t.Fatal("no-op block cryptor changed payload")
	}
}

func TestAVCSampleAESPatternLeavesShortNALClear(t *testing.T) {
	input := bytes.Repeat([]byte{0x55}, avcProbeSize-1)
	block := &recordingBlockCryptor{}
	pattern := newAVCSampleAESPattern(block)
	var output []byte

	for _, b := range input {
		if err := pattern.WriteByte(b, func(b byte) {
			output = append(output, b)
		}); err != nil {
			t.Fatal(err)
		}
	}
	pattern.Finish(func(b byte) {
		output = append(output, b)
	})

	if block.resets != 0 || len(block.blocks) != 0 {
		t.Fatal("short NAL was encrypted")
	}
	if !bytes.Equal(output, input) {
		t.Fatal("short NAL changed")
	}
}
