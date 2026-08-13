# mpegenc

Go library for streaming encryption of MPEG-TS chunks using HLS Sample AES.

## Supported codecs

- H.264/AVC
- AAC in ADTS
- AC-3

Unsupported elementary streams are passed through unchanged.

AAC signaling in the output is always written as AAC-LC. HE-AAC and HE-AACv2 extension signaling from the input is not preserved.

## Current limitations

- Encryption only. 
- Only 188-byte MPEG-TS packets are supported. 192-byte and 204-byte packet formats are not supported.
- Only MPEG-TS program number `1` is processed.
- A PMT section must fit into a single TS packet. Growing beyond one 188-byte packet normally requires an unusually large number of elementary streams or descriptors, so this is rare for typical HLS chunks.
- The elementary stream layout must not change within a chunk. Media streams are initialized from the first PMT.
