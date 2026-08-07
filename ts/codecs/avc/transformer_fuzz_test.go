package avc

import (
	"bytes"
	"testing"
)

type fuzzBlockCryptor struct{}

func (*fuzzBlockCryptor) Reset() error {
	return nil
}

func (*fuzzBlockCryptor) CryptBlocks([]byte) error {
	return nil
}

func FuzzTransformerDoesNotPanic(f *testing.F) {
	f.Add([]byte{0x67, 0x11, 0x22, 0x00, 0x00, 0x01, 0x61, 0x33}, uint16(5), false)
	f.Add(append([]byte{0x65}, bytes.Repeat([]byte{0x55}, 48)...), uint16(20), true)
	f.Add([]byte{}, uint16(0), true)

	f.Fuzz(func(t *testing.T, data []byte, split uint16, pesBoundary bool) {
		payload := append([]byte{0x00, 0x00, 0x01}, data...)
		cut := int(split) % (len(payload) + 1)
		transformer := newTransformer(&pesHandlerEvents{}, &fuzzBlockCryptor{})
		if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
			return
		}
		if err := transformer.PESPayload(payload[:cut]); err != nil {
			return
		}
		if pesBoundary {
			if err := transformer.PESEnd(); err != nil {
				return
			}
			if err := transformer.PESHeader(testVideoPESHeader()); err != nil {
				return
			}
		}
		if err := transformer.PESPayload(payload[cut:]); err != nil {
			return
		}
		if err := transformer.PESEnd(); err != nil {
			return
		}
		_ = transformer.Flush()
	})
}
