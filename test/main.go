package main

import (
	replay "github.com/aschepis/pcapreplay"
	"github.com/aschepis/netfilter"
	"fmt"
)

func main() {
	fmt.Println("pcap version: ", replay.PcapVersion())
	reader, err := replay.NewPacketReader("./test_traffic.pcapng")
	if err != nil {
		panic(err)
	}
	defer reader.Close()


	filter := netfilter.NewIPFilter()
	go filter.Run()
	defer filter.Stop()

	for {
		hdr, packet, err := reader.NextPacket()
		if err != nil {
			panic(err)
		} else if hdr == nil {
			break //eof
		}

		filter.In <- packet

		// ipHeader := netfilter.NewIPHeader(packet[14:])
		// fmt.Printf("IP Protocol Version: %v\n", ipHeader.Version())
		// fmt.Printf("Protocol: %v\n", ipHeader.Protocol)
		// fmt.Printf("Total Length: %v\n", ipHeader.TotalLength)
		// fmt.Printf("%v -> %v\n\n", ipHeader.SourceIP(), ipHeader.DestIP())
	}
}
