package ac3

import "testing"

type fuzzBlockCryptor struct{}

func (*fuzzBlockCryptor) Reset() error {
	return nil
}

func (*fuzzBlockCryptor) CryptBlocks([]byte) error {
	return nil
}

func FuzzTransformerDoesNotPanic(f *testing.F) {
	f.Add(ac3Frame(0), uint16(23), false)
	f.Add(ac3Frame(4), uint16(40), true)
	f.Add([]byte{}, uint16(0), true)

	f.Fuzz(func(t *testing.T, data []byte, split uint16, pesBoundary bool) {
		cut := int(split) % (len(data) + 1)
		transformer := NewTransformer(
			&pesHandler{},
			&fuzzBlockCryptor{},
			discardPMTPatch,
		)
		if err := transformer.PESHeader(pesHeader()); err != nil {
			return
		}
		if err := transformer.PESPayload(data[:cut]); err != nil {
			return
		}
		if pesBoundary {
			if err := transformer.PESEnd(); err != nil {
				return
			}
			if err := transformer.PESHeader(pesHeader()); err != nil {
				return
			}
		}
		if err := transformer.PESPayload(data[cut:]); err != nil {
			return
		}
		if err := transformer.PESEnd(); err != nil {
			return
		}
		_ = transformer.Flush()
	})
}
