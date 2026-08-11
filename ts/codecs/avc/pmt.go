package avc

import "github.com/bldsoft/mpegenc/internal/go-astits"

const sampleAESStreamType astits.StreamType = 0xDB

func patchPMT(stream *astits.PMTElementaryStream) {
	stream.StreamType = sampleAESStreamType
	stream.ElementaryStreamDescriptors = append(stream.ElementaryStreamDescriptors, &astits.Descriptor{
		Tag:    astits.DescriptorTagPrivateDataIndicator,
		Length: 4,
		PrivateDataIndicator: &astits.DescriptorPrivateDataIndicator{
			Indicator: 0x7A617663,
		},
	})
}
