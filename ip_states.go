package netfilter

import (
	"fmt"

	"github.com/aschepis/netfilter/ip"
	"github.com/aschepis/netfilter/tcp"
)

func stateValidateHeader(filter *Filter) stateFn {
	// read the minimum number of bytes to validate the ip header
	numBytes := ip.MIN_HEADER_LENGTH
	header := ip.NewHeader(filter.stream.Next(numBytes))

	// validate the ip haeder
	if header.ValidChecksum {
		filter.iphdr = header
		// see if there is more ip header to read.
		restOfHdr := int(header.HeaderLen()) - numBytes
		if restOfHdr == 0 {
			return stateReadPacket
		} else {
			return readStateFn(restOfHdr, consumeStreamStateFn(restOfHdr, stateReadPacket))
		}
	}

	// ip header was invalid.. return nil.
	// TODO: real error handling (e.g. find next ethernet frame)
	return nil
	// remainingBytes := math.MaxInt(0, int(header.TotalLen)-filter.stream.Len())
	// fmt.Printf("invalid ip header. skipping %v bytes.. is this right?\n", remainingBytes)
	// if remainingBytes == 0 {
	// 	return skipLinkLayerStateFn()
	// }
	// return skipStateFn(remainingBytes, skipLinkLayerStateFn())
}

func stateReadPacket(filter *Filter) stateFn {
	toRead := filter.iphdr.DataLen() - filter.stream.Len()
	if toRead > 0 {
		return readStateFn(filter.iphdr.DataLen(), stateHandlePacket)
	}
	return stateHandlePacket
}

func stateHandlePacket(filter *Filter) stateFn {
	len := int(filter.iphdr.DataLen())
	packetData := filter.stream.Next(len)

	fmt.Println("IP Protocol:", filter.iphdr.Protocol)
	switch filter.iphdr.Protocol {
	case ip.PROTO_TCP:
		tcpHdr := tcp.NewHeader(packetData)
		fmt.Println("TCP")
		fmt.Println("\tSrc:", tcpHdr.SrcPort)
		fmt.Println("\tDst:", tcpHdr.DstPort)
	case ip.PROTO_UDP:
		fmt.Println("\tUDP")
	}

	return stateIPPacketComplete
}

func stateIPPacketComplete(filter *Filter) stateFn {
	toSkip := LINK_LAYER_LEN - filter.stream.Len()
	if toSkip > 0 {
		fmt.Println("need to skip:", toSkip)
		ipHeaderToRead := ip.MIN_HEADER_LENGTH - toSkip
		var next stateFn
		if ipHeaderToRead > 0 {
			next = readStateFn(ipHeaderToRead, stateValidateHeader)
		} else {
			next = stateValidateHeader
		}
		return skipStateFn(toSkip, next)
	}

	ipHeaderToRead := ip.MIN_HEADER_LENGTH - filter.stream.Len()
	var next stateFn
	if ipHeaderToRead > 0 {
		next = readStateFn(ipHeaderToRead, stateValidateHeader)
	} else {
		next = consumeStreamStateFn(LINK_LAYER_LEN, stateValidateHeader)
	}
	return next
}
