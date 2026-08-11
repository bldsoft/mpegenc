package aac

import (
	"github.com/bldsoft/mpegenc/internal/go-astits"
	"github.com/bldsoft/mpegenc/ts/internal/pmtsignal"
)

const sampleAESStreamType astits.StreamType = 0xCF

// TODO support HE-AAC, HE-AACv2
func patchPMT(config [2]byte) pmtsignal.Patch {
	return func(stream *astits.PMTElementaryStream) {
		setup := []byte{
			'z', 'a', 'a', 'c',
			0, 0,
			1,
			2,
			config[0], config[1],
		}
		stream.StreamType = sampleAESStreamType
		stream.ElementaryStreamDescriptors = append(stream.ElementaryStreamDescriptors,
			&astits.Descriptor{
				Tag:    astits.DescriptorTagPrivateDataIndicator,
				Length: 4,
				PrivateDataIndicator: &astits.DescriptorPrivateDataIndicator{
					Indicator: 0x61616364,
				},
			},
			&astits.Descriptor{
				Tag:    astits.DescriptorTagRegistration,
				Length: uint8(4 + len(setup)),
				Registration: &astits.DescriptorRegistration{
					FormatIdentifier:             0x61706164,
					AdditionalIdentificationInfo: setup,
				},
			},
		)
	}
}
