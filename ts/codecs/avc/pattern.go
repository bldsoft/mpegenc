package avc

import "mpegenc/sampleaes"

const (
	avcProbeSize       = 49
	avcClearLead       = 32
	avcBlockSize       = 16
	avcPatternSkipSize = 9 * avcBlockSize
)

// avcSampleAESPattern selects protected bytes inside one eligible AVC NAL unit.
// Only partial probe or AES-block state is retained between writes.
type avcSampleAESPattern struct {
	block sampleaes.BlockCryptor

	protected bool
	probe     [avcProbeSize]byte
	probeLen  int
	probeEnds []int
	crypt     [avcBlockSize]byte
	cryptLen  int
	cryptEnds []int
	skip      int
}

func newAVCSampleAESPattern(block sampleaes.BlockCryptor) avcSampleAESPattern {
	return avcSampleAESPattern{block: block}
}

func (p *avcSampleAESPattern) Reset() {
	block := p.block
	*p = avcSampleAESPattern{block: block}
}

func (p *avcSampleAESPattern) WriteByte(
	b byte,
	emit func(byte),
	emitBoundary ...func() error,
) error {
	boundary := func() error { return nil }
	if len(emitBoundary) > 0 {
		boundary = emitBoundary[0]
	}
	if !p.protected {
		p.probe[p.probeLen] = b
		p.probeLen++
		if p.probeLen < len(p.probe) {
			return nil
		}
		if err := p.block.Reset(); err != nil {
			return err
		}
		if err := p.block.CryptBlocks(p.probe[avcClearLead : avcClearLead+avcBlockSize]); err != nil {
			return err
		}
		if err := emitPatternBytes(p.probe[:], p.probeEnds, emit, boundary); err != nil {
			return err
		}
		p.probeLen = 0
		p.probeEnds = p.probeEnds[:0]
		p.protected = true
		p.skip = avcPatternSkipSize - 1
		return nil
	}
	if p.skip > 0 {
		emit(b)
		p.skip--
		return nil
	}
	if p.cryptLen == len(p.crypt) {
		if err := p.block.CryptBlocks(p.crypt[:]); err != nil {
			return err
		}
		if err := emitPatternBytes(p.crypt[:], p.cryptEnds, emit, boundary); err != nil {
			return err
		}
		p.cryptLen = 0
		p.cryptEnds = p.cryptEnds[:0]
		p.skip = avcPatternSkipSize - 1
		emit(b)
		return nil
	}
	p.crypt[p.cryptLen] = b
	p.cryptLen++
	return nil
}

func (p *avcSampleAESPattern) Boundary(emit func() error) error {
	if !p.protected && p.probeLen > 0 {
		p.probeEnds = append(p.probeEnds, p.probeLen)
		return nil
	}
	if p.protected && p.cryptLen > 0 {
		p.cryptEnds = append(p.cryptEnds, p.cryptLen)
		return nil
	}
	return emit()
}

func (p *avcSampleAESPattern) Finish(
	emit func(byte),
	emitBoundary ...func() error,
) error {
	boundary := func() error { return nil }
	if len(emitBoundary) > 0 {
		boundary = emitBoundary[0]
	}
	if !p.protected {
		if err := emitPatternBytes(
			p.probe[:p.probeLen],
			p.probeEnds,
			emit,
			boundary,
		); err != nil {
			return err
		}
		p.probeLen = 0
		p.probeEnds = p.probeEnds[:0]
		return nil
	}
	if err := emitPatternBytes(
		p.crypt[:p.cryptLen],
		p.cryptEnds,
		emit,
		boundary,
	); err != nil {
		return err
	}
	p.cryptLen = 0
	p.cryptEnds = p.cryptEnds[:0]
	return nil
}

func emitPatternBytes(
	data []byte,
	boundaries []int,
	emit func(byte),
	emitBoundary func() error,
) error {
	boundary := 0
	for i := 0; i <= len(data); i++ {
		for boundary < len(boundaries) && boundaries[boundary] == i {
			if err := emitBoundary(); err != nil {
				return err
			}
			boundary++
		}
		if i < len(data) {
			emit(data[i])
		}
	}
	return nil
}
