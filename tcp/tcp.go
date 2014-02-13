package tcp

import "encoding/binary"

type Header struct {
	SrcPort            uint16
	DstPort            uint16
	Seq                uint32
	Ack                uint32
	OffetReservedFlags uint16
	Window             uint16
	Checksum           uint16
	Urgent             uint16
	// Options
}

func NewHeader(data []byte) *Header {
	// le := binary.LittleEndian
	be := binary.BigEndian
	return &Header{
		SrcPort: be.Uint16(data[0:]),
		DstPort: be.Uint16(data[2:]),
	}
}
