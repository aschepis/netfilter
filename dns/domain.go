package dns

import "strings"

type Domain struct {
	Labels []Label
}

func NewDomain(packet []byte, offset int) (Domain, int, error) {
	labels, offset, err := ReadLabels(packet, offset)
	domain := Domain{
		Labels: labels,
	}
	return domain, offset, err
}

func (domain Domain) String() string {
	var labels []string
	for _, l := range domain.Labels {
		labels = append(labels, l.Data)
	}
	return strings.Join(labels, ".")
}
