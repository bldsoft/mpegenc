package transformer

import (
	"fmt"

	"github.com/bldsoft/mpegenc/internal/go-astits"

	"github.com/bldsoft/mpegenc/sampleaes"
	"github.com/bldsoft/mpegenc/ts/codecs"
	"github.com/bldsoft/mpegenc/ts/codecs/aac"
	"github.com/bldsoft/mpegenc/ts/codecs/avc"
	"github.com/bldsoft/mpegenc/ts/internal/pmtsignal"
	"github.com/bldsoft/mpegenc/ts/packets"
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
