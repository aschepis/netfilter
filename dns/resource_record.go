package dns

import (
	"encoding/binary"
	"fmt"

	"github.com/aschepis/netfilter/ip"
)

type ResourceRecord struct {
	Domain
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    interface{}
}

func NewResourceRecord(packet []byte, offset int) (ResourceRecord, int) {
	record := ResourceRecord{}

	domain, offset, _ := NewDomain(packet, offset)
	record.Domain = domain

	be := binary.BigEndian
	record.Type = be.Uint16(packet[offset:])
	offset += 2

	record.Class = be.Uint16(packet[offset:])
	offset += 2

	record.TTL = be.Uint32(packet[offset:])
	offset += 4

	record.RDLength = be.Uint16(packet[offset:])
	offset += 2

	offset = record.makeRData(packet, offset)

	return record, offset
}

func (record *ResourceRecord) makeRData(packet []byte, offset int) int {
	switch record.Type {
	case 1:
		be := binary.BigEndian
		addr4 := ip.Addr4(be.Uint32(packet[offset:]))
		record.RData = ip.NewAddr4(addr4)
	case 5:
		domain, _, _ := NewDomain(packet, offset)
		record.RData = domain
	}
	return offset + int(record.RDLength)
}

func (record ResourceRecord) String() string {
	return fmt.Sprintf("%v %v %v: %v", record.Domain,
		record.ClassName(),
		record.TypeName(),
		record.RData)
}

func (record ResourceRecord) TypeName() string {
	return Types[record.Type]
}

func (record ResourceRecord) ClassName() string {
	return Classes[record.Class]
}
