package packets

import "testing"

func FuzzPSISectionCollectorDoesNotPanic(f *testing.F) {
	f.Add([]byte{0, 0x00, 0xB0, 0x00}, uint16(1), true, false)
	f.Add([]byte{2, 0}, uint16(1), true, true)
	f.Add([]byte{}, uint16(0), false, true)

	f.Fuzz(func(t *testing.T, data []byte, split uint16, firstPUSI, secondPUSI bool) {
		cut := int(split) % (len(data) + 1)
		collector := &psiSectionCollector{}
		if _, err := collector.Consume(firstPUSI, data[:cut]); err != nil {
			return
		}
		_, _ = collector.Consume(secondPUSI, data[cut:])
	})
}
