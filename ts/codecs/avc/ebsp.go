package avc

// ebspEscaper incrementally converts RBSP bytes back to EBSP form.
type ebspEscaper struct {
	zeroRun int
}

func (e *ebspEscaper) Reset() {
	*e = ebspEscaper{}
}

func (e *ebspEscaper) Append(dst, data []byte) []byte {
	for _, b := range data {
		dst = e.AppendByte(dst, b)
	}
	return dst
}

func (e *ebspEscaper) AppendByte(dst []byte, b byte) []byte {
	if e.zeroRun >= 2 && b <= 3 {
		dst = append(dst, 3)
		e.zeroRun = 0
	}
	dst = append(dst, b)
	if b == 0 {
		e.zeroRun = min(e.zeroRun+1, 2)
	} else {
		e.zeroRun = 0
	}
	return dst
}
