package codecs

import "mpegenc/ts/packets"

type MediaTransformer interface {
	packets.PESHandler
	Flush() error
}
