package netfilter

import (
	"bytes"
	"fmt"
	// ds "github.com/aschepis/gocommons/lang"
)

const (
	LINK_LAYER_SIZE = 14
)

type stateFn func(*IPFilter) stateFn

type IPFilter struct {
	In     chan []byte
	quit   chan bool
	stream *bytes.Buffer
}

func NewIPFilter() *IPFilter {
	return &IPFilter{
		In:     make(chan []byte),
		quit:   make(chan bool),
		stream: new(bytes.Buffer),
	}
}

func (filter *IPFilter) startState() stateFn {
	return stateInit
}

func (filter *IPFilter) Stop() {
	filter.quit <- true
}

func (filter *IPFilter) Run() {
	for state := filter.startState(); state != nil; {
		state = state(filter)
	}
}

func stateInit(filter *IPFilter) stateFn {
	select {
	case quit := <-filter.quit:
		if quit {
			return nil
		}
	case data := <-filter.In:
		filter.stream.Write(data)
		if filter.stream.Len() < MIN_HEADER_LENGTH + LINK_LAYER_SIZE {
			return stateInit
		}
		return stateValidateHeader
	}
	return nil
}

func stateValidateHeader(filter *IPFilter) stateFn {
	numBytes := MIN_HEADER_LENGTH + LINK_LAYER_SIZE
	header := NewIPHeader(filter.stream.Next(numBytes)[LINK_LAYER_SIZE:])
	if header.ValidChecksum {
		return statePacket
	}

	return nil
}

func statePacket(filter *IPFilter) stateFn {
	fmt.Println("wooooo!!!")
	return nil
}

/////
//////////////////
/*	for {
		select {
		case data := <-filter.In:
			filter.stream.Write(data)
			for {
				switch filter.state {
				case IPFILTER_INIT:

				case IPFILTER_PACKET:

				}
				break exitStateLoop
			}
exitStateLoop:
			if filter.state == IPFILTER_INIT {
				if len(stream) > 0 {
					filter.stream.Write(data)
					data = stream
				}
				if len(data) >= MIN_HEADER_LENGTH {
					// validate packet.
					header := NewIPHeader(data)
					if header.Valid() {

					}

					// consume if invalid???
					// transition state
				}
				else {
					// buffer the data for later
				}
			}

			if filter.state == IPFILTER_PROCESSING_PACKET {

			}
			// we read a packet (or part of a packet)
			err := filter.onNewData(data)
			if err != nil {
				if noData, ok := err.(ErrNotEnoughData); ok {
					panic(fmt.Sprintf("not enough data.. you need to implement a buffer: %v", noData))
				}
			}
		case quit := <-filter.quit:
			if quit {
				break
			}
		}
	}

/*
func (filter *IPFilter) onNewData(data []byte) error {
	stream, err := filter.getStream(data)
	// connection := filter.
	// connection := filter.getConnection()
	// if filter.stack.Len() == 0 {
	// 	if !filter.initConnection() {
	// 		return fmt.Errorf("Failed to recognize connection")
	// 	}
	// }

	// data := filter.stack.Peek()
	// protocolHandler := data.(ProtocolIPFilter)
	// filter.stack.Pop()
	// return protocolHandler.Process(filter)

	return nil
}

func (filter *IPFilter) getStream(data []byte) (*Connection, error) {
	// check if this is an IP packet
	buf := bytes.NewBuffer(data)
	p := NewIPProtocolHandler()
	match, err := p.Identify(buf)

	if !match {
		return nil, nil
	}

	// TODO
	return nil, nil
}
*/
