package netfilter

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

const (
	FILTER_READ_LEN = 512
)

type stateFn2 func(*Filter2) stateFn2

type Filter2 struct {
	In   chan []byte
	quit chan bool
	buf  *Buffer

	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
	parser  gopacket.Parser
}

func NewFilter2() *Filter2 {
	b, _ := NewBuffer()
	return &Filter2{
		In:   make(chan []byte),
		quit: make(chan bool),
		buf:  b,
	}
}

func (filter *Filter2) startState() stateFn2 {
	return stateRead
}

func (filter *Filter2) Stop() {
	filter.quit <- true
}

func (filter *Filter2) Run() {
	for state := filter.startState(); state != nil; {
		state = state(filter)
	}
}

func stateRead(filter *Filter2) stateFn {
	select {
	case data := <-filter.In:
		filter.buf.Write(data)
		return stateDecode
	case quit := <-filter.quit:
		if quit {
			return nil
		}
	}
	return nil
}

func stateDecode(filter *Filter2) stateFn {
	data := filter.buf.Next(64)

}
