package ts

import (
	"context"
	"fmt"
	"io"
	"mpegenc/sampleaes"

	"mpegenc/internal/go-astits"
)

func Encrypt(ctx context.Context, r io.Reader, w io.Writer, cfg sampleaes.Config) error {
	return process(ctx, r, w, cfg, true)
}

// TODO support decryption
func decrypt(ctx context.Context, r io.Reader, w io.Writer, cfg sampleaes.Config) error {
	return process(ctx, r, w, cfg, false)
}

func process(ctx context.Context, r io.Reader, w io.Writer, cfg sampleaes.Config, encrypt bool) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Set packet size to 188 bytes beforehand to avoid auto-detecting the packet size
	// Auto-detect discards second packet thus breaking everything
	dmx := astits.NewDemuxer(ctx, r, astits.DemuxerOptPacketSize(astits.MpegTsPacketSize))
	remuxer := newRemuxer(astits.NewMuxer(ctx, w), !encrypt, cfg)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		packet, err := dmx.NextPacket()
		if err == astits.ErrNoMorePackets {
			break
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("ts: demux: %w", err)
		}
		if err := remuxer.Consume(packet); err != nil {
			return err
		}
	}
	return remuxer.Flush()
}
