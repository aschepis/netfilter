package netfilter

import (
	"bytes"

	"github.com/aschepis/netfilter/ip"

	// ds "github.com/aschepis/gocommons/lang"
)

const (
	LINK_LAYER_LEN = 14
)

type stateFn func(*Filter) stateFn

type Filter struct {
	In     chan []byte
	quit   chan bool
	stream *bytes.Buffer

	iphdr *ip.Header
}

func NewFilter() *Filter {
	return &Filter{
		In:     make(chan []byte),
		quit:   make(chan bool),
		stream: new(bytes.Buffer),
	}
}

func (filter *Filter) startState() stateFn {
	return skipLinkLayerStateFn()
}

func (filter *Filter) Stop() {
	filter.quit <- true
}

func (filter *Filter) Run() {
	for state := filter.startState(); state != nil; {
		state = state(filter)
	}
}

func skipLinkLayerStateFn() stateFn {
	return skipStateFn(LINK_LAYER_LEN,
		readStateFn(ip.MIN_HEADER_LENGTH, stateValidateHeader))
}
