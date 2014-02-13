package ip

import (
	math "github.com/cznic/mathutil"
)

// unique identifier for an IP stream between two IP addresses.
type StreamId uint64

func streamId(header *Header) StreamId {
	min := math.MinUint64(uint64(header.Source), uint64(header.Dest))
	max := math.MaxUint64(uint64(header.Source), uint64(header.Dest))
	return StreamId(min<<32 | max)
}
