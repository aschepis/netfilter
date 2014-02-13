package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	PACKET_TYPE_REQUEST  = 0
	PACKET_TYPE_RESPONSE = 1
)

const (
	RESPONSE_CODE_NO_ERROR        = 0
	RESPONSE_CODE_FORMAT_ERROR    = 1
	RESPONSE_CODE_SERVER_ERROR    = 2
	RESPONSE_CODE_NAME_ERROR      = 3
	RESPONSE_CODE_NOT_IMPLEMENTED = 4
	RESPONSE_CODE_REFUSED         = 5
)

type Header struct {
	ID      uint16
	info    uint8
	rcode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func NewHeader(data []byte) Header {
	be := binary.BigEndian
	hdr := Header{
		ID:      be.Uint16(data),
		info:    data[2],
		rcode:   data[3],
		QDCount: be.Uint16(data[4:]),
		ANCount: be.Uint16(data[6:]),
		NSCount: be.Uint16(data[8:]),
		ARCount: be.Uint16(data[10:]),
	}
	return hdr
}

func (header Header) PacketType() uint8 {
	return header.info & 0x01
}

func (header Header) PacketTypeString() string {
	if header.PacketType() == PACKET_TYPE_REQUEST {
		return "Request"
	}
	return "Response"
}

func (header Header) OpCode() uint8 {
	// keep the 4 bits we want.
	return (header.info & 0x1E >> 1)
}

func (header Header) IsAuthoritativeAnswer() bool {
	// TODO
	return false
}

func (header Header) IsTruncated() bool {
	// TODO
	return false
}

func (header Header) IsRecursionDesired() bool {
	// TODO
	return false
}

func (header Header) IsRecursionAvailable() bool {
	// TODO
	return false
}

func (header Header) ResponseCode() uint8 {
	// TODO
	return 0
}

func (header Header) String() string {
	return header.indentedString(0)
}

func (header Header) indentedString(depth int) string {
	indent := strings.Repeat("  ", depth)
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%vID: %v\n", indent, header.ID))
	buf.WriteString(fmt.Sprintf("%vPacketType: %v\n", indent, header.PacketTypeString()))
	buf.WriteString(fmt.Sprintf("%vOpCode: %v\n", indent, header.OpCode()))
	buf.WriteString(fmt.Sprintf("%vQDCount: %v\n", indent, header.QDCount))
	buf.WriteString(fmt.Sprintf("%vANCount: %v\n", indent, header.ANCount))
	buf.WriteString(fmt.Sprintf("%vNSCount: %v\n", indent, header.NSCount))
	buf.WriteString(fmt.Sprintf("%vARCount: %v\n", indent, header.ARCount))
	return buf.String()
}
