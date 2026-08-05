package pmtsignal

import "mpegenc/internal/go-astits"

type Patch func(*astits.PMTElementaryStream)

type Signal func(Patch) error
