package dns

import "fmt"

var NO_MORE_LABELS = fmt.Errorf("no more labels")

type Label struct {
	Length byte
	Data   string
}

func NewLabel(data []byte) (Label, error) {
	label := Label{}
	var err error

	len := data[0]
	if len == 0 {
		err = NO_MORE_LABELS
	} else {
		label.Length = len
		label.Data = string(data[1 : len+1])
	}

	return label, err
}

func (label Label) String() string {
	return label.Data
}

func (label Label) DataLength() byte {
	return label.Length + 1
}
