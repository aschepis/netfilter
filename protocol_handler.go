package netfilter

import (
	"bytes"
)

type ProtocolHandler interface {
	Process(data []byte, filter *IPFilter) error
	Identify(stream *bytes.Buffer) (bool, error)
}
