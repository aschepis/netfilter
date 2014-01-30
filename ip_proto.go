package netfilter

import (
	"encoding/binary"
	"fmt"
)

const (
	MIN_HEADER_LENGTH = 20
	MAX_HEADER_LENGTH = 24
	PROTOCOL_TCP      = 4
)

type IPAddr uint32
type IPHeader struct {
	VersionIHL         byte
	Tos                byte
	TotalLength        uint16
	Identification     uint16
	FlagsFragOffset    uint16
	TTL                byte
	Protocol           byte
	Checksum           uint16
	Source             IPAddr
	Dest               IPAddr
	Options            uint64

	ValidChecksum      bool
}

func NewIPHeader(packet []byte) *IPHeader {
	header := &IPHeader{}
	header.VersionIHL = packet[0]
	header.Tos = packet[1]

	le := binary.LittleEndian
	be := binary.BigEndian

	header.TotalLength = be.Uint16(packet[2:])
	header.Identification = le.Uint16(packet[4:])
	header.FlagsFragOffset = le.Uint16(packet[6:])
	header.TTL = packet[8]
	header.Protocol = packet[9]
	header.Checksum = le.Uint16(packet[10:])
	header.Source = IPAddr(be.Uint32(packet[12:]))
	header.Dest = IPAddr(be.Uint32(packet[16:]))
	// header.Options = le.Uint64(packet[20:])

	header.ValidChecksum = validChecksum(packet)

	return header
}

func (header *IPHeader) Version() byte {
	return header.VersionIHL >> 4
}

func formatIP(ip IPAddr) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24),
		byte(ip>>16), byte(ip>>8),
		byte(ip))
}

func (header *IPHeader) SourceIP() string {
	return formatIP(header.Source)
}

func (header *IPHeader) DestIP() string {
	return formatIP(header.Dest)
}

func (header *IPHeader) IHL() uint8 {
	return header.VersionIHL & 0x0F
}

func (header *IPHeader) HeaderLength() uint16 {
	if header.IHL() > 5 {
		return 24
	}
	return 20
}

// func calculateChecksum(data []byte) uint16 {
// 	fn := func(v []byte) uint32 { return uint32(binary.LittleEndian.Uint16(v))}
// 	checksum := uint32(fn(data[0:]) + fn(data[2:]) +
// 		fn(data[4:]) + fn(data[6:]) +
// 		fn(data[8:]) + fn(data[12:]) +
// 		fn(data[14:]) + fn(data[16:]) +
// 		fn(data[18:]))
// 	carry := checksum >> 16
// 	checksum = checksum & 0x0FFFF
// 	checksum = ^(carry + checksum)

// 	return uint16(checksum)
// }

func validChecksum(data []byte) bool {
	fn := func(v []byte) uint32 { return uint32(binary.LittleEndian.Uint16(v))}
	checksum := uint32(fn(data[0:]) + fn(data[2:]) +
		fn(data[4:]) + fn(data[6:]) +
		fn(data[8:]) + + fn(data[10:]) +
		fn(data[12:]) + fn(data[14:]) +
		fn(data[16:]) + fn(data[18:]))
	carry := checksum >> 16
	checksum = checksum & 0x0FFFF
	result := ^uint16(carry + checksum)

	return result == 0
}
