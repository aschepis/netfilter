package dns

import (
	"encoding/binary"
	"fmt"
)

type Question struct {
	Domain
	Type  uint16
	Class uint16
}

func NewQuestion(packet []byte, offset int) (Question, int) {
	question := Question{}
	domain, offset, _ := NewDomain(packet, offset)
	question.Domain = domain

	be := binary.BigEndian
	question.Type = be.Uint16(packet[offset:])
	offset += 2

	question.Class = be.Uint16(packet[offset:])
	offset += 2

	return question, offset
}

func (question Question) String() string {
	return fmt.Sprintf("%v %v %v", question.Domain,
		question.ClassName(),
		question.TypeName(),
	)
}

func (question Question) TypeName() string {
	return Types[question.Type]
}

func (question Question) ClassName() string {
	return Classes[question.Class]
}
