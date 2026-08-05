package transformer

import (
	"fmt"

	"mpegenc/internal/go-astits"

	"mpegenc/sampleaes"
	"mpegenc/ts/codecs"
	"mpegenc/ts/codecs/aac"
	"mpegenc/ts/codecs/avc"
	"mpegenc/ts/internal/pmtsignal"
	"mpegenc/ts/packets"
)

func NewTransformer(
	streamType astits.StreamType,
	next packets.PESHandler,
	cfg sampleaes.Config,
	signal pmtsignal.Signal,
) (codecs.MediaTransformer, error) {
	switch streamType {
	case astits.StreamTypeH264Video:
		return avc.NewTransformer(next, sampleaes.NewCBCEncryptor(cfg), signal)
	case astits.StreamTypeADTS:
		return aac.NewTransformer(next, sampleaes.NewCBCEncryptor(cfg), signal), nil
	default:
		return nil, fmt.Errorf("unsupported media stream type 0x%02X", streamType)
	}
}

func SupportedMediaType(streamType astits.StreamType, inputEncrypted bool) bool {
	return streamType == astits.StreamTypeH264Video ||
		(!inputEncrypted && streamType == astits.StreamTypeADTS)
}
