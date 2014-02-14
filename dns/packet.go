package dns

import (
	"bytes"
	"fmt"
)

const (
	HEADER_LEN = 12
)

type Packet struct {
	Header
	Questions         []Question
	Answers           []ResourceRecord
	NameServers       []ResourceRecord
	AdditionalRecords []ResourceRecord
}

func NewPacket(packetData []byte) (*Packet, error) {
	packet := &Packet{
		Header: NewHeader(packetData),
	}

	q, offset, _ := unpackQuestions(packet.Header.QDCount, packetData, HEADER_LEN)
	packet.Questions = q

	r, offset, _ := unpackRecords(packet.Header.ANCount, packetData, offset)
	packet.Answers = r

	r, offset, _ = unpackRecords(packet.Header.NSCount, packetData, offset)
	packet.NameServers = r

	r, offset, _ = unpackRecords(packet.Header.ARCount, packetData, offset)
	packet.AdditionalRecords = r

	return packet, nil
}

func unpackQuestions(count uint16, packetData []byte, offset int) ([]Question, int, error) {
	questions := make([]Question, 0)
	for i := 0; i < int(count); i++ {
		question, newOffset := NewQuestion(packetData, offset)
		offset = newOffset
		questions = append(questions, question)
	}

	return questions, offset, nil
}

func unpackRecords(count uint16, packetData []byte, offset int) ([]ResourceRecord, int, error) {
	records := make([]ResourceRecord, 0)
	for i := 0; i < int(count); i++ {
		record, newOffset := NewResourceRecord(packetData, offset)
		offset = newOffset
		records = append(records, record)
	}

	return records, offset, nil
}

func (packet *Packet) IsValid() bool {
	return false
}

func (packet *Packet) String() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Header:\n%v\n", packet.Header.indentedString(1)))
	buf.WriteString(fmt.Sprintf("Questions: %v\n", packet.Questions))
	buf.WriteString(fmt.Sprintf("Answers: %v\n", packet.Answers))
	buf.WriteString(fmt.Sprintf("NameServers: %v\n", packet.NameServers))
	buf.WriteString(fmt.Sprintf("AdditionalRecords: %v\n", packet.AdditionalRecords))

	return buf.String()
}
