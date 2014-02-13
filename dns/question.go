package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type Question struct {
	Labels []Label
	Type   uint16
	Class  uint16
}

func NewQuestion(data []byte) (Question, int) {
	question := Question{}

	offset := 0
	for {
		label, err := NewLabel(data[offset:])
		if err == NO_MORE_LABELS {
			offset += 1
			break
		}

		question.Labels = append(question.Labels, label)
		offset += int(label.DataLength())
	}

	be := binary.BigEndian
	question.Type = be.Uint16(data[offset:])
	offset += 2

	question.Class = be.Uint16(data[offset:])
	offset += 2

	return question, offset
}

func (question Question) Domain() string {
	var labels []string
	for _, l := range question.Labels {
		labels = append(labels, l.Data)
	}
	return strings.Join(labels, ".")
}

func (question Question) String() string {
	return fmt.Sprintf("%v %v %v", question.Domain(), question.Type, question.Class)
}
