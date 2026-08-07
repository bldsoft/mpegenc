package packets

import "testing"

func FuzzPESCollectorDoesNotPanic(f *testing.F) {
	f.Add(pes(0, nil, []byte{1, 2, 3}), uint16(4), false)
	f.Add([]byte{0, 0, 2}, uint16(1), true)
	f.Add([]byte{}, uint16(0), false)

	f.Fuzz(func(t *testing.T, data []byte, split uint16, secondPUSI bool) {
		cut := int(split) % (len(data) + 1)
		var collector PESCollector
		var events pesEvents
		if err := collector.Consume(true, data[:cut], &events); err != nil {
			return
		}
		if err := collector.Consume(secondPUSI, data[cut:], &events); err != nil {
			return
		}
		_ = collector.Flush(&events)
	})
}
