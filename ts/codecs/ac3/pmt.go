package ac3

import (
	"github.com/bldsoft/mpegenc/internal/go-astits"
	"github.com/bldsoft/mpegenc/ts/internal/pmtsignal"
)

const sampleAESStreamType astits.StreamType = 0xC1

func patchPMT(setup [10]byte) pmtsignal.Patch {
	return func(stream *astits.PMTElementaryStream) {
		info := []byte{
			'z', 'a', 'c', '3',
			0, 0,
			1,
			10,
		}
		info = append(info, setup[:]...)
		stream.StreamType = sampleAESStreamType
		stream.ElementaryStreamDescriptors = append(stream.ElementaryStreamDescriptors,
			&astits.Descriptor{
				Tag:    astits.DescriptorTagPrivateDataIndicator,
				Length: 4,
				PrivateDataIndicator: &astits.DescriptorPrivateDataIndicator{
					Indicator: 0x61633364,
				},
			},
			&astits.Descriptor{
				Tag:    astits.DescriptorTagRegistration,
				Length: uint8(4 + len(info)),
				Registration: &astits.DescriptorRegistration{
					FormatIdentifier:             0x61706164,
					AdditionalIdentificationInfo: info,
				},
			},
		)
	}
}
