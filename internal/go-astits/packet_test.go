package astits

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/asticode/go-astikit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func packet(h PacketHeader, a PacketAdaptationField, i []byte, packet192bytes bool) ([]byte, *Packet) {
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	w.Write(uint8(syncByte)) // Sync byte
	if packet192bytes {
		w.Write([]byte("test")) // Sometimes packets are 192 bytes
	}
	w.Write(packetHeaderBytes(h, "11"))                             // Header
	w.Write(packetAdaptationFieldBytes(a))                          // Adaptation field
	var payload = append(i, bytes.Repeat([]byte{0}, 147-len(i))...) // Payload
	w.Write(payload)
	return buf.Bytes(), &Packet{
		AdaptationField: packetAdaptationField,
		Header:          packetHeader,
		Payload:         payload,
	}
}

func packetShort(h PacketHeader, payload []byte) ([]byte, *Packet) {
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	w.Write(uint8(syncByte))            // Sync byte
	w.Write(packetHeaderBytes(h, "01")) // Header
	p := append(payload, bytes.Repeat([]byte{0}, MpegTsPacketSize-buf.Len())...)
	w.Write(p)
	return buf.Bytes(), &Packet{
		Header:  h,
		Payload: payload,
	}
}

func TestParsePacket(t *testing.T) {
	// Packet not starting with a sync
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	w.Write(uint16(1)) // Invalid sync byte
	_, err := parsePacket(astikit.NewBytesIterator(buf.Bytes()), nil)
	assert.EqualError(t, err, ErrPacketMustStartWithASyncByte.Error())

	// Valid
	b, ep := packet(packetHeader, *packetAdaptationField, []byte("payload"), true)
	p, err := parsePacket(astikit.NewBytesIterator(b), nil)
	assert.NoError(t, err)
	assert.Equal(t, p, ep)

	// Skip
	_, err = parsePacket(astikit.NewBytesIterator(b), func(p *Packet) bool { return true })
	assert.EqualError(t, err, errSkippedPacket.Error())
}

func TestPayloadOffset(t *testing.T) {
	assert.Equal(t, 3, payloadOffset(0, PacketHeader{}, nil))
	assert.Equal(t, 7, payloadOffset(1, PacketHeader{HasAdaptationField: true}, &PacketAdaptationField{Length: 2}))
}

func TestWritePacket(t *testing.T) {
	eb, ep := packet(packetHeader, *packetAdaptationField, []byte("payload"), false)
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	n, err := writePacket(w, ep, MpegTsPacketSize)
	assert.NoError(t, err)
	assert.Equal(t, MpegTsPacketSize, n)
	assert.Equal(t, n, buf.Len())
	assert.Equal(t, len(eb), buf.Len())
	assert.Equal(t, eb, buf.Bytes())
}

// mpegenc's custom test for zero-length adaptation fields
func TestPacketWithZeroLengthAdaptationFieldRoundTrip(t *testing.T) {
	raw := append(
		[]byte{syncByte, 0x01, 0x00, 0x30, 0x00},
		bytes.Repeat([]byte{0xab}, 183)...,
	)

	p, err := parsePacket(astikit.NewBytesIterator(raw), nil)
	require.NoError(t, err)
	require.Len(t, p.Payload, 183)

	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	_, err = writePacket(w, p, MpegTsPacketSize)
	require.NoError(t, err)
	assert.Equal(t, raw, buf.Bytes())
}

func TestWritePacket_HeaderOnly(t *testing.T) {
	shortPacketHeader := packetHeader
	shortPacketHeader.HasPayload = false
	shortPacketHeader.HasAdaptationField = false
	_, ep := packetShort(shortPacketHeader, nil)

	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})

	n, err := writePacket(w, ep, MpegTsPacketSize)
	assert.NoError(t, err)
	assert.Equal(t, MpegTsPacketSize, n)
	assert.Equal(t, n, buf.Len())

	// we can't just compare bytes returned by packetShort since they're not completely correct,
	//  so we just cross-check writePacket with parsePacket
	i := astikit.NewBytesIterator(buf.Bytes())
	p, err := parsePacket(i, nil)
	assert.NoError(t, err)
	assert.Equal(t, ep, p)
}

func TestClonePacket(t *testing.T) {
	original := &Packet{
		AdaptationField: packetAdaptationField,
		Header:          packetHeader,
		Payload:         []byte("payload"),
	}
	cloned := ClonePacket(original)

	assert.Equal(t, original, cloned)
	assert.False(t, original == cloned)
	assert.False(t, original.AdaptationField == cloned.AdaptationField)
	assert.False(t, original.AdaptationField.PCR == cloned.AdaptationField.PCR)
	assert.False(t, original.AdaptationField.OPCR == cloned.AdaptationField.OPCR)
	assert.False(
		t,
		original.AdaptationField.AdaptationExtensionField ==
			cloned.AdaptationField.AdaptationExtensionField,
	)
	assert.False(
		t,
		original.AdaptationField.AdaptationExtensionField.DTSNextAccessUnit ==
			cloned.AdaptationField.AdaptationExtensionField.DTSNextAccessUnit,
	)

	cloned.Payload[0] = 'X'
	cloned.AdaptationField.PCR.Base++
	cloned.AdaptationField.OPCR.Extension++
	cloned.AdaptationField.TransportPrivateData[0] = 'X'
	cloned.AdaptationField.AdaptationExtensionField.DTSNextAccessUnit.Base++

	assert.Equal(t, byte('p'), original.Payload[0])
	assert.NotEqual(t, cloned.AdaptationField.PCR.Base, original.AdaptationField.PCR.Base)
	assert.NotEqual(t, cloned.AdaptationField.OPCR.Extension, original.AdaptationField.OPCR.Extension)
	assert.Equal(t, byte('t'), original.AdaptationField.TransportPrivateData[0])
	assert.NotEqual(
		t,
		cloned.AdaptationField.AdaptationExtensionField.DTSNextAccessUnit.Base,
		original.AdaptationField.AdaptationExtensionField.DTSNextAccessUnit.Base,
	)
}

var packetHeader = PacketHeader{
	ContinuityCounter:          10,
	HasAdaptationField:         true,
	HasPayload:                 true,
	PayloadUnitStartIndicator:  true,
	PID:                        5461,
	TransportErrorIndicator:    true,
	TransportPriority:          true,
	TransportScramblingControl: ScramblingControlScrambledWithEvenKey,
}

func packetHeaderBytes(h PacketHeader, afControl string) []byte {
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	w.Write(h.TransportErrorIndicator)                // Transport error indicator
	w.Write(h.PayloadUnitStartIndicator)              // Payload unit start indicator
	w.Write("1")                                      // Transport priority
	w.Write(fmt.Sprintf("%.13b", h.PID))              // PID
	w.Write("10")                                     // Scrambling control
	w.Write(afControl)                                // Adaptation field control
	w.Write(fmt.Sprintf("%.4b", h.ContinuityCounter)) // Continuity counter
	return buf.Bytes()
}

func TestParsePacketHeader(t *testing.T) {
	v, err := parsePacketHeader(astikit.NewBytesIterator(packetHeaderBytes(packetHeader, "11")))
	assert.Equal(t, packetHeader, v)
	assert.NoError(t, err)
}

func TestWritePacketHeader(t *testing.T) {
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	bytesWritten, err := writePacketHeader(w, packetHeader)
	assert.NoError(t, err)
	assert.Equal(t, bytesWritten, 3)
	assert.Equal(t, bytesWritten, buf.Len())
	assert.Equal(t, packetHeaderBytes(packetHeader, "11"), buf.Bytes())
}

var packetAdaptationField = &PacketAdaptationField{
	AdaptationExtensionField: &PacketAdaptationExtensionField{
		DTSNextAccessUnit:      dtsClockReference,
		HasLegalTimeWindow:     true,
		HasPiecewiseRate:       true,
		HasSeamlessSplice:      true,
		LegalTimeWindowIsValid: true,
		LegalTimeWindowOffset:  10922,
		Length:                 11,
		PiecewiseRate:          2796202,
		SpliceType:             2,
	},
	DiscontinuityIndicator:            true,
	ElementaryStreamPriorityIndicator: true,
	HasAdaptationExtensionField:       true,
	HasOPCR:                           true,
	HasPCR:                            true,
	HasTransportPrivateData:           true,
	HasSplicingCountdown:              true,
	Length:                            36,
	OPCR:                              pcr,
	PCR:                               pcr,
	RandomAccessIndicator:             true,
	SpliceCountdown:                   2,
	TransportPrivateDataLength:        4,
	TransportPrivateData:              []byte("test"),
	StuffingLength:                    5,
}

func packetAdaptationFieldBytes(a PacketAdaptationField) []byte {
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	w.Write(uint8(36))                // Length
	w.Write(a.DiscontinuityIndicator) // Discontinuity indicator
	w.Write("1")                      // Random access indicator
	w.Write("1")                      // Elementary stream priority indicator
	w.Write("1")                      // PCR flag
	w.Write("1")                      // OPCR flag
	w.Write("1")                      // Splicing point flag
	w.Write("1")                      // Transport data flag
	w.Write("1")                      // Adaptation field extension flag
	w.Write(pcrBytes())               // PCR
	w.Write(pcrBytes())               // OPCR
	w.Write(uint8(2))                 // Splice countdown
	w.Write(uint8(4))                 // Transport private data length
	w.Write([]byte("test"))           // Transport private data
	w.Write(uint8(11))                // Adaptation extension length
	w.Write("1")                      // LTW flag
	w.Write("1")                      // Piecewise rate flag
	w.Write("1")                      // Seamless splice flag
	w.Write("11111")                  // Reserved
	w.Write("1")                      // LTW valid flag
	w.Write("010101010101010")        // LTW offset
	w.Write("11")                     // Piecewise rate reserved
	w.Write("1010101010101010101010") // Piecewise rate
	w.Write(dtsBytes("0010"))         // Splice type + DTS next access unit
	w.WriteN(^uint64(0), 40)          // Stuffing bytes
	return buf.Bytes()
}

func TestParsePacketAdaptationField(t *testing.T) {
	v, err := parsePacketAdaptationField(astikit.NewBytesIterator(packetAdaptationFieldBytes(*packetAdaptationField)))
	assert.Equal(t, packetAdaptationField, v)
	assert.NoError(t, err)
}

func TestWritePacketAdaptationField(t *testing.T) {
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	eb := packetAdaptationFieldBytes(*packetAdaptationField)
	bytesWritten, err := writePacketAdaptationField(w, packetAdaptationField)
	assert.NoError(t, err)
	assert.Equal(t, bytesWritten, buf.Len())
	assert.Equal(t, len(eb), buf.Len())
	assert.Equal(t, eb, buf.Bytes())
}

func TestHasAdaptationFieldData(t *testing.T) {
	assert.False(t, HasAdaptationFieldData(nil))
	assert.False(t, HasAdaptationFieldData(&PacketAdaptationField{
		StuffingLength: 5,
	}))
	assert.True(t, HasAdaptationFieldData(packetAdaptationField))
}

func TestCloneAdaptationFieldWithoutStuffing(t *testing.T) {
	cloned := CloneAdaptationFieldWithoutStuffing(packetAdaptationField)
	require.NotNil(t, cloned)
	assert.Equal(t, 0, cloned.Length)
	assert.Equal(t, 0, cloned.StuffingLength)
	assert.False(t, cloned.IsOneByteStuffing)
	assert.False(t, packetAdaptationField.PCR == cloned.PCR)
	assert.False(t, packetAdaptationField.OPCR == cloned.OPCR)
	assert.False(
		t,
		packetAdaptationField.AdaptationExtensionField ==
			cloned.AdaptationExtensionField,
	)
	assert.False(
		t,
		packetAdaptationField.AdaptationExtensionField.DTSNextAccessUnit ==
			cloned.AdaptationExtensionField.DTSNextAccessUnit,
	)

	cloned.PCR.Base++
	cloned.OPCR.Extension++
	cloned.TransportPrivateData[0] = 'X'
	cloned.AdaptationExtensionField.DTSNextAccessUnit.Base++

	assert.NotEqual(t, cloned.PCR.Base, packetAdaptationField.PCR.Base)
	assert.NotEqual(t, cloned.OPCR.Extension, packetAdaptationField.OPCR.Extension)
	assert.Equal(t, byte('t'), packetAdaptationField.TransportPrivateData[0])
	assert.NotEqual(
		t,
		cloned.AdaptationExtensionField.DTSNextAccessUnit.Base,
		packetAdaptationField.AdaptationExtensionField.DTSNextAccessUnit.Base,
	)
}

func TestAdaptationFieldSizeWithoutStuffing(t *testing.T) {
	assert.Equal(t, 0, AdaptationFieldSizeWithoutStuffing(nil))
	assert.Equal(t, 32, AdaptationFieldSizeWithoutStuffing(packetAdaptationField))
}

func serializedAdaptationFieldSize(
	t *testing.T,
	field *PacketAdaptationField,
) int {
	t.Helper()
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	written, err := writePacketAdaptationField(w, field)
	require.NoError(t, err)
	assert.Equal(t, written, buf.Len())
	return written
}

func TestAdaptationFieldWithSize(t *testing.T) {
	field, err := AdaptationFieldWithSize(packetAdaptationField, 37)
	require.NoError(t, err)
	assert.Equal(t, 5, field.StuffingLength)
	assert.Equal(t, 37, serializedAdaptationFieldSize(t, field))
	assert.Equal(t, 5, packetAdaptationField.StuffingLength)

	minimum, err := AdaptationFieldWithSize(packetAdaptationField, 32)
	require.NoError(t, err)
	assert.Equal(t, 32, serializedAdaptationFieldSize(t, minimum))
}

func TestAdaptationFieldWithSizeRejectsUndersizedTarget(t *testing.T) {
	field, err := AdaptationFieldWithSize(packetAdaptationField, 31)
	assert.Nil(t, field)
	assert.EqualError(
		t,
		err,
		"astits: adaptation field requires 32 bytes, target size is 31",
	)
}

func TestNewStuffingAdaptationField(t *testing.T) {
	oneByte, err := NewStuffingAdaptationField(1)
	require.NoError(t, err)
	assert.True(t, oneByte.IsOneByteStuffing)
	assert.Equal(t, 1, serializedAdaptationFieldSize(t, oneByte))

	regular, err := NewStuffingAdaptationField(10)
	require.NoError(t, err)
	assert.Equal(t, 8, regular.StuffingLength)
	assert.Equal(t, 10, serializedAdaptationFieldSize(t, regular))

	maximum, err := NewStuffingAdaptationField(maxPacketAdaptationFieldSize)
	require.NoError(t, err)
	assert.Equal(
		t,
		maxPacketAdaptationFieldSize,
		serializedAdaptationFieldSize(t, maximum),
	)
}

func TestNewStuffingAdaptationFieldRejectsInvalidSize(t *testing.T) {
	for _, size := range []int{0, MpegTsPacketSize - 3} {
		field, err := NewStuffingAdaptationField(size)
		assert.Nil(t, field)
		assert.Error(t, err)
	}
}

var pcr = &ClockReference{
	Base:      5726623061,
	Extension: 341,
}

func pcrBytes() []byte {
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	w.Write("101010101010101010101010101010101") // Base
	w.Write("111111")                            // Reserved
	w.Write("101010101")                         // Extension
	return buf.Bytes()
}

func TestParsePCR(t *testing.T) {
	v, err := parsePCR(astikit.NewBytesIterator(pcrBytes()))
	assert.Equal(t, pcr, v)
	assert.NoError(t, err)
}

func TestWritePCR(t *testing.T) {
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	bytesWritten, err := writePCR(w, pcr)
	assert.NoError(t, err)
	assert.Equal(t, bytesWritten, 6)
	assert.Equal(t, bytesWritten, buf.Len())
	assert.Equal(t, pcrBytes(), buf.Bytes())
}

func BenchmarkWritePCR(b *testing.B) {
	buf := &bytes.Buffer{}
	buf.Grow(6)
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		writePCR(w, pcr)
	}
}

func BenchmarkParsePacket(b *testing.B) {
	bs, _ := packet(packetHeader, *packetAdaptationField, []byte("payload"), true)

	for i := 0; i < b.N; i++ {
		b.ReportAllocs()
		parsePacket(astikit.NewBytesIterator(bs), nil)
	}
}
