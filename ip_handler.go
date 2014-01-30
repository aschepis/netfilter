package netfilter

import (
	"bytes"
	"fmt"
)

type IPProtocolHandler struct {
	lastIPHeader   *IPHeader
	lastPacketData []byte
}

func NewIPProtocolHandler() *IPProtocolHandler {
	return &IPProtocolHandler{}
}

func (h *IPProtocolHandler) Identify(stream *bytes.Buffer) (bool, error) {
	potentialPacket := stream.Next(46)
	match := false
	if len(potentialPacket) == 46 {
		h.lastIPHeader = NewIPHeader(potentialPacket[14:48])
		if h.lastIPHeader.Version() == 4 {
			fmt.Println("IP Packet: ", h.lastIPHeader.Version(),
				h.lastIPHeader.Protocol, h.lastIPHeader.SourceIP(),
				h.lastIPHeader.DestIP(), "len:", h.lastIPHeader.TotalLength)
			if h.lastPacketData == nil || len(h.lastPacketData) < int(h.lastIPHeader.TotalLength) {
				h.lastPacketData = make([]byte, h.lastIPHeader.TotalLength)
			}
			match = true
		}
	}
	return match, nil
}

func (h *IPProtocolHandler)	Process(data []byte, filter *IPFilter) error {
	// consume IP header
	// handler.Read(h.lastPacketData[0:h.lastIPHeader.HeaderLength()])

	// payloadSize := h.lastIPHeader.TotalLength - h.lastIPHeader.HeaderLength()
	// bytesRead, _ := handler.Read(h.lastPacketData[:payloadSize])

	// // push correct kind of header based on protocol
	// switch h.lastIPHeader.Protocol {
	// case 6:
	// 	fmt.Println("payload: ", string(h.lastPacketData[:bytesRead]))
	// }

	return nil
}
