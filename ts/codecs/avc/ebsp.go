package avc

import "bytes"

type ebspEscaper struct {
	zeroRun int
}

func (e *ebspEscaper) Reset() {
	*e = ebspEscaper{}
}

func (e *ebspEscaper) Append(dst, data []byte) []byte {
	for len(data) > 0 {
		if e.zeroRun == 2 {
			b := data[0]
			if b <= 3 {
				dst = append(dst, 3)
			}
			dst = append(dst, b)
			if b == 0 {
				e.zeroRun = 1
			} else {
				e.zeroRun = 0
			}
			data = data[1:]
			continue
		}
		if e.zeroRun == 1 {
			if data[0] == 0 {
				dst = append(dst, 0)
				e.zeroRun = 2
				data = data[1:]
				continue
			}
			e.zeroRun = 0
		}
		i := bytes.Index(data, []byte{0, 0})
		if i < 0 {
			dst = append(dst, data...)
			if data[len(data)-1] == 0 {
				e.zeroRun = 1
			}
			return dst
		}
		dst = append(dst, data[:i+2]...)
		e.zeroRun = 2
		data = data[i+2:]
	}
	return dst
}
