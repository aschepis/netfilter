package dns

import "encoding/binary"

type ResourceRecord struct {
	Name     []Label
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

func NewResourceRecord(data []byte) (ResourceRecord, int) {
	record := ResourceRecord{}

	offset := 0
	for {
		label, err := NewLabel(data[offset:])
		if err == NO_MORE_LABELS {
			offset += 1
			break
		}

		record.Name = append(record.Name, label)
		offset += int(label.DataLength())
	}

	be := binary.BigEndian
	record.Type = be.Uint16(data[offset:])
	offset += 2

	record.Class = be.Uint16(data[offset:])
	offset += 2

	record.TTL = be.Uint32(data[offset:])
	offset += 4

	record.RDLength = be.Uint16(data[offset:])
	offset += 2

	record.RData = data[offset : offset+int(record.RDLength)]
	offset += int(record.RDLength)
	return record, offset
}
