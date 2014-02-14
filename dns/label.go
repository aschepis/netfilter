package dns

type Label struct {
	Length byte
	Data   string
}

func ReadLabels(packet []byte, offset int) ([]Label, int, error) {
	var labels []Label

	for {
		label := Label{}
		labelLength := packet[offset]
		if labelLength == 0 {
			offset += 1
			break
		} else if (labelLength & 0xc0) == 0xc0 {
			// compression
			ptrOffset := int(labelLength&0x3f)<<8 + int(packet[offset+1])
			pointerLabels, _, _ := ReadLabels(packet, ptrOffset)
			labels = append(labels, pointerLabels...)
			offset += 2
			break
		} else {
			label.Length = labelLength
			label.Data = string(packet[offset+1 : offset+int(labelLength)+1])
			offset += int(labelLength + 1)
			labels = append(labels, label)
		}
	}
	return labels, offset, nil
}

func (label Label) String() string {
	return label.Data
}

func (label Label) DataLength() byte {
	return label.Length + 1
}
