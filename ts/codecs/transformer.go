package codecs

import "github.com/bldsoft/mpegenc/ts/packets"

type MediaTransformer interface {
	packets.PESHandler
	Flush() error
}
