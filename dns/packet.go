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

	packetData = packetData[HEADER_LEN:]

	q, packetData, _ := unpackQuestions(packet.Header.QDCount, packetData)
	packet.Questions = q

	r, packetData, _ := unpackRecords(packet.Header.ANCount, packetData)
	packet.Answers = r

	r, packetData, _ = unpackRecords(packet.Header.ANCount, packetData)
	packet.NameServers = r

	r, packetData, _ = unpackRecords(packet.Header.ANCount, packetData)
	packet.AdditionalRecords = r

	return packet, nil
}

func unpackQuestions(count uint16, packetData []byte) ([]Question, []byte, error) {
	questions := make([]Question, 0)
	for i := 0; i < int(count); i++ {
		question, size := NewQuestion(packetData)
		packetData = packetData[size:]
		questions = append(questions, question)
	}

	return questions, packetData, nil
}

func unpackRecords(count uint16, packetData []byte) ([]ResourceRecord, []byte, error) {
	records := make([]ResourceRecord, 0)
	for i := 0; i < int(count); i++ {
		record, size := NewResourceRecord(packetData)
		packetData = packetData[size:]
		records = append(records, record)
	}

	return records, packetData, nil
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
