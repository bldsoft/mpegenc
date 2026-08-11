package pmtsignal

import "github.com/bldsoft/mpegenc/internal/go-astits"

type Patch func(*astits.PMTElementaryStream)

type Signal func(Patch) error
